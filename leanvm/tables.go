package leanvm

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
)

// The instruction tables: one per class, all of the same shape: the state step, the bytecode read,
// two register reads and one register write. What a class computes is its circuit, and every word
// the circuit reads or writes is a column here that lives in the circuit's packed witness. This
// follows python-verifier/verifier.py.

const (
	logRegisters = 6
	clockStride  = 4
	ramSlot      = 2
	hashWords    = 16
	hashOutWord  = 4
	hashStride   = 2 + hashWords
	rangeLog     = 16
	kBits        = 64
	flockKSkip   = 6 // log2(kBits)
	logPacking   = 6
	flockMinLog  = 13
	maxLogRows   = 32
	numFramework = 10
	syscallReg   = 17
	sysExit      = 93
)

var registerSlots = []int{0, 1, 3}

// The framework columns, which no instruction table owns.
const (
	colRegisterFinal = iota
	colRegisterFinalTS
	colRAMFinal
	colRAMFinalTS
	colAdviceInitial
	colAdviceFinal
	colAdviceFinalTS
	colBytecodeFinal
	colRangeLoFinal
	colRangeHiFinal
)

var outputRegisters = []int{10, 11, 12, 13}

// Bus separators.
var (
	sepState    = extOne
	sepMem      = extGen
	sepBytecode = lift(gpow(2))
	sepRangeLo  = lift(gpow(3))
	sepRangeHi  = lift(gpow(4))
	sepReg      = lift(gpow(5))
)

// rangeHiRatio is g^(-2^16).
var rangeHiRatio = extGen.inv().pow(1 << rangeLog)

// monomial is a constant (a = b = -1), a column (b = -1), or a product of two columns (a <= b).
type monomial struct{ a, b int }

var constMonomial = monomial{-1, -1}

// form is a polynomial of degree at most 2 in a table's columns.
type form map[monomial]ext

func (f form) addScaled(other form, weight ext) {
	for m, c := range other {
		f[m] = f[m].add(weight.mul(c))
	}
}

func (f form) plus(other form) form {
	out := form{}
	out.addScaled(f, extOne)
	out.addScaled(other, extOne)
	return out
}

func (f form) evaluate(column []ext) ext {
	var out ext
	for m, c := range f {
		switch {
		case m.a < 0:
			out = out.add(c)
		case m.b < 0:
			out = out.add(c.mul(column[m.a]))
		default:
			out = out.add(c.mul(column[m.a]).mul(column[m.b]))
		}
	}
	return out
}

func constForm(v ext) form {
	return form{constMonomial: v}
}

func colForm(i int, exponent int) form {
	return form{monomial{i, -1}: lift(gpow(uint64(exponent)))}
}

func prodForm(a, b int, exponent int) form {
	return form{monomial{min(a, b), max(a, b)}: lift(gpow(uint64(exponent)))}
}

type flushes struct {
	push, pull [][]form
}

func (f *flushes) pair(push, pull []form) {
	f.push = append(f.push, push)
	f.pull = append(f.pull, pull)
}

// counted is a read of a lookup array: pulled with its count, pushed back with the count advanced.
func (f *flushes) counted(prefix []form, count int, suffix []form) {
	f.pair(slices.Concat(prefix, []form{colForm(count, 1)}, suffix), slices.Concat(prefix, []form{colForm(count, 0)}, suffix))
}

// ram describes how a class uses RAM.
type ram int

const (
	ramNone ram = iota
	ramRead
	ramWrite
	ramBlock
)

var accessKinds = []string{"x", "lo", "hi", "cnt_lo", "cnt_hi"}

// table is one instruction class's table.
type table struct {
	name       string
	opcode     int
	control    bool
	ram        ram
	ports      []string // the circuit's port words in order: a column each, or "" for a hint
	columns    []string
	slots      []int
	circuit    *circuit
	flushes    flushes
	countCols  []int
	constraint [][4]int // per access: x, lo, hi columns, and the access's clock slot
	tsCol      int
}

func (t *table) col(name string) int {
	i := slices.Index(t.columns, name)
	if i < 0 {
		panic(fmt.Sprintf("leanvm: table %s has no column %s", t.name, name))
	}
	return i
}

func (t *table) width() int { return len(t.columns) }

func (t *table) slotBits() int { return t.circuit.logSize - logPacking }

// minLogHeight: a batch is at least eight instances, and the zerocheck's cube at least 2^13 bits.
func (t *table) minLogHeight() int { return max(3, flockMinLog-t.circuit.logSize) }

func (t *table) hasPort(name string) bool { return slices.Contains(t.ports, name) }

func ramColumns(r ram) []string {
	switch r {
	case ramRead:
		return []string{"address", "cell_0"}
	case ramWrite:
		return []string{"address", "cell_0", "cell_new_0"}
	case ramBlock:
		var out []string
		for k := range hashWords {
			out = append(out, fmt.Sprintf("cell_%d", k))
		}
		for j := range 4 {
			out = append(out, fmt.Sprintf("cell_new_%d", hashOutWord+j))
		}
		return out
	}
	return nil
}

func ramSlots(r ram) []int {
	if r == ramBlock {
		out := slices.Clone(registerSlots[:2])
		for k := range hashWords {
			out = append(out, 2+k)
		}
		return out
	}
	if len(ramColumns(r)) > 0 {
		return append(slices.Clone(registerSlots), ramSlot)
	}
	return slices.Clone(registerSlots)
}

func newTable(name string, opcode int, control bool, r ram, c *circuit, ports []string) *table {
	t := &table{name: name, opcode: opcode, control: control, ram: r, circuit: c, ports: ports}
	cols := []string{"pc", "ts", "a1", "a2", "pc4", "v1", "v2", "flags"}
	if r != ramBlock {
		cols = append(cols, "ad", "vd_old", "out")
	}
	if control {
		cols = append(cols, "dt", "link", "jalr", "taken", "exit")
	}
	if t.hasPort("imm") {
		cols = append(cols, "imm")
	}
	cols = append(cols, ramColumns(r)...)
	if t.hasPort("bad") {
		cols = append(cols, "bad")
	}
	t.slots = ramSlots(r)
	for _, kind := range accessKinds {
		for i := range t.slots {
			cols = append(cols, fmt.Sprintf("%s_%d", kind, i))
		}
	}
	cols = append(cols, "cnt_bc")
	t.columns = cols
	for i, name := range cols {
		if strings.HasPrefix(name, "cnt") {
			t.countCols = append(t.countCols, i)
		}
	}
	t.tsCol = t.col("ts")
	for i, slot := range t.slots {
		t.constraint = append(t.constraint, [4]int{t.col(fmt.Sprintf("x_%d", i)), t.col(fmt.Sprintf("lo_%d", i)), t.col(fmt.Sprintf("hi_%d", i)), slot})
	}
	t.buildFlushes()
	return t
}

// constraints are one identity per access, x * lo = g^slot * ts * hi.
func (t *table) constraints(row []ext) []ext {
	out := make([]ext, len(t.constraint))
	for i, c := range t.constraint {
		out[i] = row[c[0]].mul(row[c[1]]).add(lift(gpow(uint64(c[3]))).mul(row[t.tsCol]).mul(row[c[2]]))
	}
	return out
}

// access is access number access of the row, at clock slot slot: pull the cell as its previous
// access left it, push it back at this access's timestamp, and read the gap's two chunks off the
// range arrays.
func (t *table) access(f *flushes, separator ext, address form, access, slot int, old, new form) {
	ts := t.col("ts")
	x, lo, hi := t.col(fmt.Sprintf("x_%d", access)), t.col(fmt.Sprintf("lo_%d", access)), t.col(fmt.Sprintf("hi_%d", access))
	cntLo, cntHi := t.col(fmt.Sprintf("cnt_lo_%d", access)), t.col(fmt.Sprintf("cnt_hi_%d", access))
	f.pair([]form{constForm(separator), address, colForm(ts, slot), new}, []form{constForm(separator), address, colForm(x, 0), old})
	f.counted([]form{constForm(sepRangeLo), colForm(lo, 0)}, cntLo, nil)
	f.counted([]form{constForm(sepRangeHi), colForm(hi, 0)}, cntHi, nil)
}

func (t *table) buildFlushes() {
	c := func(name string) form { return colForm(t.col(name), 0) }
	npc, vd, stride := c("pc4"), constForm(extZero), clockStride
	adForm, immForm := constForm(lift(sink)), constForm(extZero)
	var fields []form
	if t.ram != ramBlock {
		adForm, vd = c("ad"), c("out")
	}
	if t.hasPort("imm") {
		immForm = c("imm")
	}
	if t.control {
		taken, dt, jalr, out, pc4, link := t.col("taken"), t.col("dt"), t.col("jalr"), t.col("out"), t.col("pc4"), t.col("link")
		npc = c("pc4").plus(prodForm(taken, dt, 0)).plus(prodForm(jalr, out, 0)).plus(prodForm(jalr, pc4, 0))
		vd = c("out").plus(prodForm(link, out, 0)).plus(prodForm(link, pc4, 0))
		fields = []form{c("dt"), c("link"), c("jalr")}
	}
	if t.ram == ramBlock {
		stride = hashStride
	}
	f := &t.flushes
	exitMarker := constForm(extZero)
	if t.control {
		exitMarker = prodForm(t.col("exit"), t.col("ts"), stride)
	}
	f.pair(
		[]form{constForm(sepState), npc, colForm(t.col("ts"), stride), exitMarker},
		[]form{constForm(sepState), c("pc"), c("ts"), constForm(extZero)},
	)
	entry := []form{constForm(lift(gpow(uint64(t.opcode)))), c("flags"), c("a1"), c("a2"), adForm, immForm, c("pc4")}
	entry = append(entry, fields...)
	if t.hasPort("bad") {
		for len(entry) < badSlot-3 {
			entry = append(entry, constForm(extZero))
		}
		entry = append(entry, c("bad"))
	}
	for len(entry) < exitSlot-3 {
		entry = append(entry, constForm(extZero))
	}
	if t.control {
		entry = append(entry, c("exit"))
	} else {
		entry = append(entry, constForm(extZero))
	}
	f.counted([]form{constForm(sepBytecode), c("pc")}, t.col("cnt_bc"), entry)
	t.access(f, sepReg, c("a1"), 0, registerSlots[0], c("v1"), c("v1"))
	t.access(f, sepReg, c("a2"), 1, registerSlots[1], c("v2"), c("v2"))
	if t.ram != ramBlock {
		t.access(f, sepReg, c("ad"), 2, registerSlots[2], c("vd_old"), vd)
	}
	if t.ram == ramRead || t.ram == ramWrite {
		cols := ramColumns(t.ram)
		t.access(f, sepMem, c("address"), 3, ramSlot, c("cell_0"), c(cols[len(cols)-1]))
	}
	if t.ram == ramBlock {
		for k := range hashWords {
			old := c(fmt.Sprintf("cell_%d", k))
			new := old
			if hashOutWord <= k && k < hashOutWord+4 {
				new = c(fmt.Sprintf("cell_new_%d", k))
			}
			t.access(f, sepMem, c("v1").plus(constForm(lift(uint64(8*k)))), 2+k, 2+k, old, new)
		}
	}
}

var (
	tablesOnce sync.Once
	allTables  [numTables]*table
	// globalBases are each table's first global column: after the framework columns and one packed
	// flock witness per table.
	globalBases [numTables]int
)

func classTables() *[numTables]*table {
	tablesOnce.Do(func() {
		cs := classCircuits()
		hashPorts := []string{"v2", "flags"}
		for _, k := range []int{0, 1, 2, 3, 8, 9, 10, 11, 12, 13, 14, 15} {
			hashPorts = append(hashPorts, fmt.Sprintf("cell_%d", k))
		}
		for j := range 4 {
			hashPorts = append(hashPorts, fmt.Sprintf("cell_new_%d", hashOutWord+j))
		}
		allTables = [numTables]*table{
			newTable("alu", classALU, true, ramNone, cs[classALU], []string{"v1", "v2", "imm", "flags", "out", "taken"}),
			newTable("load", classLoad, false, ramRead, cs[classLoad], []string{"v1", "imm", "flags", "cell_0", "address", "out"}),
			newTable("store", classStore, false, ramWrite, cs[classStore], []string{"v1", "v2", "imm", "flags", "cell_0", "address", "cell_new_0", "out"}),
			newTable("shift", classShift, false, ramNone, cs[classShift], []string{"v1", "v2", "imm", "flags", "out"}),
			newTable("mul", classMul, false, ramNone, cs[classMul], []string{"v1", "v2", "flags", "out"}),
			newTable("mulh", classMulh, false, ramNone, cs[classMulh], []string{"v1", "v2", "flags", "out"}),
			newTable("div", classDiv, false, ramNone, cs[classDiv], []string{"v1", "v2", "flags", "", "", "out", "bad"}),
			newTable("hash", classHash, false, ramBlock, cs[classHash], hashPorts),
		}
		next := numFramework + numTables
		for t, tb := range allTables {
			globalBases[t] = next
			next += tb.width()
		}
	})
	return &allTables
}

// placement is where a column sits in the stacked cube: a claim's point fills the variables
// coordinates above low, the bits of index fixing the rest. low is zero for a block with a cube of
// its own, and the slot width for a circuit word interleaved into its table's packed witness.
type placement struct {
	variables int
	index     int
	low       int
}

func selectorPoint(selector, length int) []ext {
	out := make([]ext, length)
	for bit := range out {
		if selector>>bit&1 == 1 {
			out[bit] = extOne
		}
	}
	return out
}

func (p placement) stackPoint(point []ext, stackLog int) []ext {
	bits := selectorPoint(p.index, stackLog)
	return slices.Concat(bits[:p.low], point, bits[p.low+p.variables:])
}

// eqAbove is the eq weight of the coordinates above the window.
func (p placement) eqAbove(point []ext) ext {
	above := p.low + p.variables
	if above >= len(point) {
		return extOne
	}
	return eqEval(selectorPoint(p.index>>above, len(point)-above), point[above:])
}

// stackOffsets lays 2^size blocks end to end, largest first, ties by index, and returns the
// offsets and the total.
func stackOffsets(sizes []int) ([]int, uint64) {
	order := make([]int, len(sizes))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool { return sizes[order[i]] > sizes[order[j]] })
	offsets := make([]int, len(sizes))
	var total uint64
	for _, i := range order {
		offsets[i] = int(total)
		total += uint64(1) << sizes[i]
	}
	return offsets, total
}

// busBlock is one block of a bus side, owned by a table: it flushes 2^logRows rows of coordinates,
// forms over the owner's own columns.
type busBlock struct {
	logRows     int
	coordinates []form
	owner       int
}

// layout is the public structure the verifier rebuilds from the program and the announced sizes.
type layout struct {
	prog         *program
	push, pull   []busBlock
	count        []busBlock
	placements   []placement
	stackLog     int
	nLanes       int
	tableHeights [numTables]int
	finalClock   ext
}

// minStackedLog and maxStackedLog bound the committed stack's log size.
const (
	minStackedLog = 15
	maxStackedLog = 28
	logBatch      = 6
)

// buildLayout validates the announced sizes and rebuilds the layout. It returns false if a table
// height is outside its bounds or the stack is outside the PCS window.
func buildLayout(p *program, heights [numTables]int, finalClock ext) (*layout, bool) {
	tables := classTables()
	for t, tb := range tables {
		if heights[t] < tb.minLogHeight() || heights[t] > maxLogRows {
			return nil, false
		}
	}
	l := &layout{prog: p, tableHeights: heights, finalClock: finalClock}
	for t, tb := range tables {
		for _, coords := range tb.flushes.push {
			l.push = append(l.push, busBlock{heights[t], coords, t})
		}
		for _, coords := range tb.flushes.pull {
			l.pull = append(l.pull, busBlock{heights[t], coords, t})
		}
		for _, local := range tb.countCols {
			l.count = append(l.count, busBlock{heights[t], []form{colForm(local, 0)}, t})
		}
	}

	logBC := p.logBytecode()
	kappas := []int{logRegisters, logRegisters, p.logRAM, p.logRAM, p.logAdvice, p.logAdvice, p.logAdvice, logBC, rangeLog, rangeLog}
	for t, tb := range tables {
		kappas = append(kappas, heights[t]+tb.slotBits())
	}
	for t, tb := range tables {
		for range tb.width() {
			kappas = append(kappas, heights[t])
		}
	}
	// A circuit word is no block of its own: it is committed inside its table's packed witness.
	type word struct{ table, port int }
	words := map[int]word{}
	for t, tb := range tables {
		for port, name := range tb.ports {
			if name != "" {
				words[globalBases[t]+tb.col(name)] = word{t, port}
			}
		}
	}
	var blockCols, blockSizes []int
	for col, kappa := range kappas {
		if _, ok := words[col]; !ok {
			blockCols = append(blockCols, col)
			blockSizes = append(blockSizes, kappa)
		}
	}
	offsets, total := stackOffsets(blockSizes)
	offsetOf := map[int]int{}
	for i, col := range blockCols {
		offsetOf[col] = offsets[i]
	}
	l.stackLog = max(minStackedLog, log2Ceil(total))
	if l.stackLog > maxStackedLog {
		return nil, false
	}
	// The committed lanes: the stack rounded up to whole 2^(mu - 6)-word lanes; the rest are zero
	// and never committed.
	lane := uint64(1) << (l.stackLog - logBatch)
	l.nLanes = int(max(1, (total+lane-1)/lane))
	l.placements = make([]placement, len(kappas))
	for col, kappa := range kappas {
		if w, ok := words[col]; ok {
			tb := tables[w.table]
			l.placements[col] = placement{kappa, offsetOf[numFramework+w.table] + w.port, tb.slotBits()}
		} else {
			l.placements[col] = placement{kappa, offsetOf[col], 0}
		}
	}
	return l, true
}
