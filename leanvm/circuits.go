package leanvm

import (
	"math/bits"
	"sort"
	"sync"
)

// The class circuits, as gate lists. One instance is the circuit's ports, whole 64-bit words each
// (the inputs, then the outputs), then the constant wire, then the circuit's products in the order
// they are made. A wire is the gate that drives it: a free committed wire (an input bit or the
// constant), an uncommitted XOR, an AND whose product is committed at a slot, or a copy that commits
// an affine wire at a slot, which is how a result leaves. What has to agree with the prover is the
// port layout and the order products are made in. This follows python-verifier/verifier.py, which
// leanVM pins against its Rust circuits.

const (
	gateFree = iota
	gateXor
	gateAnd
	gateCopy
)

type gate struct {
	kind int
	x, y int
	slot int
}

// wire is a gate index, or none for a structural zero.
type wire = int

const none wire = -1

type gateList struct {
	gates          []gate
	constantColumn int
	nextSlot       int
	one            wire
	inputs         [][]wire
	outputBases    []int
}

func newGateList(inputBits, outputBits []int) *gateList {
	c := &gateList{}
	var words []int
	for _, b := range append(append([]int{}, inputBits...), outputBits...) {
		words = append(words, (b+63)/64)
	}
	total := 0
	bases := make([]int, len(words))
	for i, w := range words {
		bases[i] = 64 * total
		total += w
	}
	c.constantColumn = 64 * total
	c.nextSlot = c.constantColumn + 1
	c.one = c.push(gateFree, c.constantColumn, 0, 0)
	for p, b := range inputBits {
		in := make([]wire, b)
		for i := range in {
			in[i] = c.push(gateFree, bases[p]+i, 0, 0)
		}
		c.inputs = append(c.inputs, in)
	}
	c.outputBases = bases[len(inputBits):]
	return c
}

func (c *gateList) logSize() int {
	return log2Ceil(uint64(c.nextSlot))
}

func (c *gateList) push(kind, x, y, slot int) wire {
	c.gates = append(c.gates, gate{kind, x, y, slot})
	return len(c.gates) - 1
}

func (c *gateList) xor(x, y wire) wire {
	if x == none {
		return y
	}
	if y == none {
		return x
	}
	return c.push(gateXor, x, y, 0)
}

func (c *gateList) invert(x wire) wire {
	return c.xor(x, c.one)
}

// product is one product, and one slot, unless an operand is a structural zero.
func (c *gateList) product(x, y wire) wire {
	if x == none || y == none {
		return none
	}
	c.nextSlot++
	return c.push(gateAnd, x, y, c.nextSlot-1)
}

func (c *gateList) either(x, y wire) wire {
	both := c.product(x, y)
	return c.xor(c.xor(x, y), both)
}

// mux is `x if select else y`, one product.
func (c *gateList) mux(sel, x, y wire) wire {
	return c.xor(c.product(sel, c.xor(x, y)), y)
}

func (c *gateList) output(port, bit int, w wire) {
	if w != none {
		c.push(gateCopy, w, 0, c.outputBases[port]+bit)
	}
}

// reduceEither folds either over ws, starting from none.
func (c *gateList) reduceEither(start wire, ws []wire) wire {
	acc := start
	for _, w := range ws {
		acc = c.either(acc, w)
	}
	return acc
}

// circuit is what the reduction needs of a class circuit.
type circuit struct {
	gates          []gate
	logSize        int
	constantColumn int
}

func (c *gateList) circuit() *circuit {
	return &circuit{gates: c.gates, logSize: c.logSize(), constantColumn: c.constantColumn}
}

// bilinear is e_row^T (A0 + alpha B0) w_col, by one forward walk: every committed wire is a row,
// whose A side is the wire's expansion against w_col and whose B side is its other factor, the
// constant for a free wire or a copy.
// Factored weights avoid constructing the padded row/column tensor products.
// A slot i has weight high[i/kBits]*low[i%kBits]; only committed slots
// contribute to the bilinear form. XOR gates remain uncommitted wires.
func (c *circuit) bilinear(alpha ext, rowHigh, rowLow, colHigh, colLow []ext) ext {
	return c.bilinearScratch(alpha, rowHigh, rowLow, colHigh, colLow, make([]ext, len(c.gates)))
}

// Each verification owns its scratch; circuit definitions are shared and immutable.
func (c *circuit) bilinearScratch(alpha ext, rowHigh, rowLow, colHigh, colLow, scratch []ext) ext {
	column := func(i int) ext { return colHigh[i/kBits].mul(colLow[i%kBits]) }
	constantScaled := alpha.mul(column(c.constantColumn))
	var total ext
	wires := scratch[:0]
	for _, g := range c.gates {
		if g.kind == gateXor {
			wires = append(wires, wires[g.x].add(wires[g.y]))
			continue
		}
		slot := g.slot
		if g.kind == gateFree {
			slot = g.x
		}
		value := column(slot)
		left, scaledRight := value, constantScaled
		if g.kind == gateAnd {
			left, scaledRight = wires[g.x], alpha.mul(wires[g.y])
		}
		if g.kind == gateCopy {
			left = wires[g.x]
		}
		wires = append(wires, value)
		weight := rowHigh[slot/kBits].mul(rowLow[slot%kBits])
		total = total.add(weight.mul(left.add(scaledRight)))
	}
	return total
}

// ALU flag bits as the circuit indexes them.
const (
	fSub = iota
	fWord
	fLT
	fLTU
	fAnd
	fOr
	fXor
	fClearBit0
	fEq
	fNe
	fBLT
	fBGE
	fBLTU
	fBGEU
	fAlways
)

// aluCircuit is (v1, v2, imm, flags) -> (out, taken).
func aluCircuit() *gateList {
	c := newGateList([]int{64, 64, 64, 15}, []int{64, 1})
	v1, v2, imm, flags := c.inputs[0], c.inputs[1], c.inputs[2], c.inputs[3]
	b := make([]wire, 64)
	for i := range b {
		b[i] = c.xor(v2[i], imm[i])
	}
	carry := flags[fSub]
	total := make([]wire, 0, 64)
	for i := range 64 {
		y := c.xor(b[i], flags[fSub])
		xc, yc := c.xor(v1[i], carry), c.xor(y, carry)
		total = append(total, c.xor(xc, y))
		carry = c.xor(c.product(xc, yc), carry)
	}
	ltu := c.invert(carry)
	lt := c.xor(ltu, c.xor(v1[63], b[63]))
	diff := make([]wire, 64)
	for i := range diff {
		diff[i] = c.xor(v1[i], b[i])
	}
	ne := c.reduceEither(none, diff)
	eq := c.invert(ne)

	for i := 32; i < 64; i++ {
		total[i] = c.mux(flags[fWord], total[31], total[i])
	}
	nonSel := c.one
	for _, bit := range []int{fLT, fLTU, fAnd, fOr, fXor} {
		nonSel = c.xor(nonSel, flags[bit])
	}
	andOr, orXor := c.xor(flags[fAnd], flags[fOr]), c.xor(flags[fOr], flags[fXor])
	out := make([]wire, 64)
	for i := range out {
		out[i] = c.product(nonSel, total[i])
	}
	for i := range 64 {
		both := c.product(v1[i], b[i])
		andTerm := c.product(andOr, both)
		out[i] = c.xor(out[i], c.xor(andTerm, c.product(orXor, diff[i])))
	}
	ltTerm := c.product(flags[fLT], lt)
	out[0] = c.xor(out[0], c.xor(ltTerm, c.product(flags[fLTU], ltu)))
	out[0] = c.product(c.invert(flags[fClearBit0]), out[0])

	taken := flags[fAlways]
	holds := []wire{eq, ne, lt, c.invert(lt), ltu, c.invert(ltu)}
	for k, bit := range []int{fEq, fNe, fBLT, fBGE, fBLTU, fBGEU} {
		taken = c.xor(taken, c.product(flags[bit], holds[k]))
	}
	for i, w := range out {
		c.output(0, i, w)
	}
	c.output(1, 0, taken)
	return c
}

// add is x + y over len(x) bits, the carry out of the top bit dropped.
func (c *gateList) add(x, y []wire) []wire {
	carry := none
	total := make([]wire, 0, len(x))
	for i := range x {
		xc, yc := c.xor(x[i], carry), c.xor(y[i], carry)
		total = append(total, c.xor(xc, y[i]))
		if i+1 < len(x) {
			carry = c.xor(c.product(xc, yc), carry)
		}
	}
	return total
}

// addWithCarry is x + y + carry, and the carry out of the top bit.
func (c *gateList) addWithCarry(x, y []wire, carry wire) ([]wire, wire) {
	total := make([]wire, 0, len(x))
	for i := range x {
		xc, yc := c.xor(x[i], carry), c.xor(y[i], carry)
		total = append(total, c.xor(xc, y[i]))
		carry = c.xor(c.product(xc, yc), carry)
	}
	return total, carry
}

// shiftBytes is x shifted by 8 * amount bits, amount being three bits.
func (c *gateList) shiftBytes(x, amount []wire, left bool) []wire {
	x = append([]wire(nil), x...)
	for stage, bit := range amount {
		by := 8 << stage
		moved := make([]wire, 64)
		for i := range moved {
			moved[i] = none
			if left && i >= by {
				moved[i] = x[i-by]
			}
			if !left && i+by < 64 {
				moved[i] = x[i+by]
			}
		}
		next := make([]wire, 64)
		for i := range next {
			next[i] = c.mux(bit, moved[i], x[i])
		}
		x = next
	}
	return x
}

// busAddress is a load's or a store's address v1 + imm, the width's thresholds (at least 2 bytes,
// at least 4, exactly 8), and what goes on the memory bus: the address with the bits that misalign
// the access left in.
func (c *gateList) busAddress(v1, imm, logWidth []wire) (address, thresholds, bus []wire) {
	address = c.add(v1, imm)
	thresholds = []wire{c.either(logWidth[0], logWidth[1]), logWidth[1], c.product(logWidth[0], logWidth[1])}
	bus = make([]wire, 0, 64)
	for i := range 3 {
		bus = append(bus, c.product(address[i], thresholds[i]))
	}
	bus = append(bus, address[3:]...)
	return address, thresholds, bus
}

// loadCircuit is (v1, imm, flags, cell) -> (address, out).
func loadCircuit() *gateList {
	c := newGateList([]int{64, 64, 3, 64}, []int{64, 64})
	v1, imm, flags, cell := c.inputs[0], c.inputs[1], c.inputs[2], c.inputs[3]
	address, th, bus := c.busAddress(v1, imm, flags[:2])
	ge2, ge4, eq8 := th[0], th[1], th[2]
	value := c.shiftBytes(cell, address[:3], false)
	sign := none
	for _, wb := range []struct {
		width wire
		bit   int
	}{{c.invert(ge2), 7}, {c.xor(ge2, ge4), 15}, {c.xor(ge4, eq8), 31}} {
		sign = c.xor(sign, c.product(wb.width, value[wb.bit]))
	}
	extension := c.product(flags[2], sign)
	for i, w := range bus {
		c.output(0, i, w)
	}
	for i := range 64 {
		if i < 8 {
			c.output(1, i, value[i])
			continue
		}
		keeps := eq8
		switch {
		case i < 16:
			keeps = ge2
		case i < 32:
			keeps = ge4
		}
		c.output(1, i, c.mux(keeps, value[i], extension))
	}
	return c
}

// storeCircuit is (v1, v2, imm, flags, cell) -> (address, new cell, out).
func storeCircuit() *gateList {
	c := newGateList([]int{64, 64, 64, 2, 64}, []int{64, 64, 64})
	v1, v2, imm, flags, cell := c.inputs[0], c.inputs[1], c.inputs[2], c.inputs[3], c.inputs[4]
	address, thresholds, bus := c.busAddress(v1, imm, flags)
	value := c.shiftBytes(v2, address[:3], true)
	var spans [3][2]wire
	for k := range 3 {
		spans[k] = [2]wire{c.either(c.invert(address[k]), thresholds[k]), c.either(address[k], thresholds[k])}
	}
	for i, w := range bus {
		c.output(0, i, w)
	}
	for j := range 8 {
		written := c.product(c.product(spans[0][j&1], spans[1][j>>1&1]), spans[2][j>>2])
		for i := 8 * j; i < 8*j+8; i++ {
			c.output(1, i, c.mux(written, value[i], cell[i]))
		}
	}
	return c
}

// sext32If is x, its bits from 32 up replaced by bit 31 when word is set.
func (c *gateList) sext32If(word wire, x []wire) []wire {
	out := append([]wire(nil), x[:32]...)
	for _, b := range x[32:] {
		out = append(out, c.mux(word, x[31], b))
	}
	return out
}

// shiftCircuit is (v1, v2, imm, flags) -> out: one right shifter for both directions.
func shiftCircuit() *gateList {
	c := newGateList([]int{64, 64, 64, 3}, []int{64})
	v1, v2, imm := c.inputs[0], c.inputs[1], c.inputs[2]
	right, arith, word := c.inputs[3][0], c.inputs[3][1], c.inputs[3][2]
	amount := make([]wire, 6)
	for i := range amount {
		amount[i] = c.xor(v2[i], imm[i])
	}
	amount[5] = c.product(c.invert(word), amount[5])
	lowSign := c.product(arith, v1[31])
	x := append([]wire(nil), v1[:32]...)
	for _, b := range v1[32:] {
		x = append(x, c.mux(word, lowSign, b))
	}
	fill := c.product(arith, x[63])
	y := make([]wire, 64)
	for i := range y {
		y[i] = c.mux(right, x[i], x[63-i])
	}
	for stage, bit := range amount {
		next := make([]wire, 64)
		for i := range next {
			from := fill
			if i+(1<<stage) < 64 {
				from = y[i+(1<<stage)]
			}
			next[i] = c.mux(bit, from, y[i])
		}
		y = next
	}
	z := make([]wire, 64)
	for i := range z {
		z[i] = c.mux(right, y[i], y[63-i])
	}
	for i, w := range c.sext32If(word, z) {
		c.output(0, i, w)
	}
	return c
}

// u128 is a 128-bit set of bit positions.
type u128 struct{ lo, hi uint64 }

func (a u128) and(b u128) u128 { return u128{a.lo & b.lo, a.hi & b.hi} }
func (a u128) or(b u128) u128  { return u128{a.lo | b.lo, a.hi | b.hi} }
func (a u128) shl1() u128      { return u128{a.lo << 1, a.hi<<1 | a.lo>>63} }
func (a u128) bit(p int) bool {
	if p >= 64 {
		return a.hi>>(p-64)&1 == 1
	}
	return a.lo>>p&1 == 1
}
func (a *u128) set(p int) {
	if p >= 64 {
		a.hi |= 1 << (p - 64)
	} else {
		a.lo |= 1 << p
	}
}

// bitLength is Python's int.bit_length.
func (a u128) bitLength() int {
	if a.hi != 0 {
		return 128 - bits.LeadingZeros64(a.hi)
	}
	return 64 - bits.LeadingZeros64(a.lo)
}

// lowBitLength is (a & -a).bit_length(): one more than the lowest set bit, zero for zero.
func (a u128) lowBitLength() int {
	if a.lo != 0 {
		return bits.TrailingZeros64(a.lo) + 1
	}
	if a.hi != 0 {
		return bits.TrailingZeros64(a.hi) + 65
	}
	return 0
}

// mask is the bits 0 to n-1.
func mask(n int) u128 {
	var m u128
	for p := range n {
		m.set(p)
	}
	return m
}

// multiply is the low n bits of a * b: twice the product as a sum of 66 rows of affine bits,
// compressed three rows into two by carry-save steps, then a ripple-carry addition. Every product
// is a majority.
func (c *gateList) multiply(a, b []wire, n int) []wire {
	notA := make([]wire, 64)
	notB := make([]wire, 64)
	for i := range 64 {
		notA[i] = c.invert(a[i])
	}
	for i := range 64 {
		notB[i] = c.invert(b[i])
	}
	g := c.product(notA[0], notB[0])

	rows := make([][]wire, 66)
	for i := range rows {
		rows[i] = make([]wire, n)
		for p := range rows[i] {
			rows[i][p] = none
		}
	}
	for i := range 64 {
		for j := range 64 {
			if p := i + j - 1; p >= 0 && p < n {
				rows[i][p] = c.xor(b[j], notA[i])
			}
		}
	}
	for _, r := range []struct {
		row       int
		low, high []wire
	}{{64, notA, a}, {65, notB, b}} {
		length := min(64, n-63)
		copy(rows[r.row][:63], r.low[1:])
		copy(rows[r.row][63:63+length], r.high[:length])
	}
	rows[2][0], rows[3][0] = c.one, g
	if n == 128 {
		rows[64][127] = c.one
	}
	present := make([]u128, 66)
	for i, row := range rows {
		for p, w := range row {
			if w != none {
				present[i].set(p)
			}
		}
	}

	live := make([]int, 66)
	for i := range live {
		live[i] = i
	}
	pairMask := mask(n - 1)
	for len(live) > 2 {
		order := make([]int, len(live))
		for t := range order {
			order[t] = t
		}
		sort.SliceStable(order, func(i, j int) bool {
			pi, pj := present[live[order[i]]], present[live[order[j]]]
			if pi.bitLength() != pj.bitLength() {
				return pi.bitLength() < pj.bitLength()
			}
			return pi.lowBitLength() < pj.lowBitLength()
		})
		x, y, z := live[order[0]], live[order[1]], live[order[2]]
		next := make([]int, 0, len(live)-1)
		for _, r := range live {
			if r != x && r != y && r != z {
				next = append(next, r)
			}
		}
		live = append(next, x, y)
		px, py, pz := present[x], present[y], present[z]
		pairs := px.and(py).or(px.and(pz)).or(py.and(pz)).and(pairMask)
		triples := px.and(py).and(pz)
		var products, moves u128
		for p := range n - 1 {
			if !pairs.bit(p) {
				continue
			}
			if !triples.bit(p) && !products.shl1().bit(p) {
				moves.set(p)
			} else {
				products.set(p)
			}
		}
		total := make([]wire, n)
		carry := make([]wire, n)
		for p := range n {
			total[p], carry[p] = none, none
		}
		for p := range n {
			wx, wy, wz := rows[x][p], rows[y][p], rows[z][p]
			switch {
			case products.bit(p):
				xz, yz := c.xor(wx, wz), c.xor(wy, wz)
				carry[p+1] = c.xor(c.product(xz, yz), wz)
				total[p] = c.xor(xz, wy)
			case moves.bit(p) && pz.bit(p):
				carry[p], total[p] = wz, c.xor(wx, wy)
			case moves.bit(p):
				carry[p], total[p] = wy, wx
			default:
				total[p] = c.xor(c.xor(wx, wz), wy)
			}
		}
		rows[x], rows[y] = total, carry
		present[x], present[y] = px.or(py).or(pz), products.shl1().or(moves)
	}

	out := make([]wire, 0, n)
	chain := none
	r0, r1 := rows[live[0]], rows[live[1]]
	for p := range n {
		wx, wy := r0[p], r1[p]
		count := 0
		for _, w := range []wire{wx, wy, chain} {
			if w != none {
				count++
			}
		}
		if p+1 < n && count >= 2 {
			xc, yc := c.xor(wx, chain), c.xor(wy, chain)
			chain = c.xor(c.product(xc, yc), chain)
			out = append(out, c.xor(xc, wy))
		} else {
			out = append(out, c.xor(c.xor(wx, wy), chain))
			chain = none
		}
	}
	return out
}

// mulCircuit is (v1, v2, flags) -> out: the low word of the product.
func mulCircuit() *gateList {
	c := newGateList([]int{64, 64, 1}, []int{64})
	for i, w := range c.sext32If(c.inputs[2][0], c.multiply(c.inputs[0], c.inputs[1], 64)) {
		c.output(0, i, w)
	}
	return c
}

// mulhCircuit is (v1, v2, flags) -> out: the high word of the product, each operand signed or not.
func mulhCircuit() *gateList {
	c := newGateList([]int{64, 64, 2}, []int{64})
	v1, v2, flags := c.inputs[0], c.inputs[1], c.inputs[2]
	high := c.multiply(v1, v2, 128)[64:]
	for _, s := range []struct {
		signed         wire
		operand, other []wire
	}{{flags[0], v1, v2}, {flags[1], v2, v1}} {
		negative := c.product(s.signed, s.operand[63])
		sub := make([]wire, 64)
		for i, b := range s.other {
			sub[i] = c.product(negative, c.invert(b))
		}
		high, _ = c.addWithCarry(high, sub, negative)
	}
	for i, w := range high {
		c.output(0, i, w)
	}
	return c
}

// negateIf is x negated if negative: (x ^ negative) + negative.
func (c *gateList) negateIf(negative wire, x []wire) []wire {
	flipped := make([]wire, len(x))
	zeros := make([]wire, len(x))
	for i, b := range x {
		flipped[i] = c.xor(b, negative)
		zeros[i] = none
	}
	out, _ := c.addWithCarry(flipped, zeros, negative)
	return out
}

// divCircuit is (v1, v2, flags, q, r) -> (out, bad).
func divCircuit() *gateList {
	c := newGateList([]int{64, 64, 3, 64, 64}, []int{64, 1})
	v1, v2 := c.inputs[0], c.inputs[1]
	signed, rem, word := c.inputs[2][0], c.inputs[2][1], c.inputs[2][2]
	q, r := c.inputs[3], c.inputs[4]

	extend := func(x []wire) []wire {
		sign := c.product(signed, x[31])
		out := append([]wire(nil), x[:32]...)
		for _, b := range x[32:] {
			out = append(out, c.mux(word, sign, b))
		}
		return out
	}
	n, d := extend(v1), extend(v2)
	nNegative, dNegative := c.product(signed, n[63]), c.product(signed, d[63])
	nAbs, dAbs := c.negateIf(nNegative, n), c.negateIf(dNegative, d)

	product := c.multiply(q, dAbs, 128)
	overflows := c.reduceEither(none, product[64:])
	total, carries := c.addWithCarry(product[:64], r, none)
	differ := make([]wire, 64)
	for i := range differ {
		differ[i] = c.xor(total[i], nAbs[i])
	}
	differs := c.reduceEither(none, differ)
	notD := make([]wire, 64)
	for i, b := range dAbs {
		notD[i] = c.invert(b)
	}
	_, tooLarge := c.addWithCarry(r, notD, c.one)
	dNonzero := c.reduceEither(none, d)
	bad := c.product(dNonzero, c.reduceEither(overflows, []wire{carries, differs, tooLarge}))

	qSigned, rSigned := c.negateIf(c.xor(nNegative, dNegative), q), c.negateIf(nNegative, r)
	out := make([]wire, 64)
	for i := range out {
		result := c.mux(rem, rSigned[i], qSigned[i])
		out[i] = c.mux(dNonzero, result, c.mux(rem, n[i], c.one))
	}
	for i, w := range c.sext32If(word, out) {
		c.output(0, i, w)
	}
	c.output(1, 0, bad)
	return c
}

var blake2sIV = [8]uint32{0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19}

var blake2sSigma = [10][16]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}

var blake2sLanes = [8][4]int{{0, 4, 8, 12}, {1, 5, 9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15}, {0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7, 8, 13}, {3, 4, 9, 14}}

// blake2sCircuit is (t, f0, h[4], m[8]) -> out[4]: the BLAKE2s compression on the 32-bit halves
// of the words.
func blake2sCircuit() *gateList {
	in := []int{64, 32}
	for range 12 {
		in = append(in, 64)
	}
	c := newGateList(in, []int{64, 64, 64, 64})
	t, f0 := c.inputs[0], c.inputs[1]
	var halves [][]wire
	for _, word := range c.inputs[2:] {
		for i := range 2 {
			halves = append(halves, append([]wire(nil), word[32*i:32*i+32]...))
		}
	}
	h, m := halves[:8], halves[8:]
	literal := func(x uint32) []wire {
		out := make([]wire, 32)
		for i := range out {
			out[i] = none
			if x>>i&1 == 1 {
				out[i] = c.one
			}
		}
		return out
	}
	rotr := func(w []wire, r int) []wire {
		out := make([]wire, 32)
		for i := range out {
			out[i] = w[(i+r)%32]
		}
		return out
	}
	xor := func(x, y []wire) []wire {
		out := make([]wire, len(x))
		for i := range x {
			out[i] = c.xor(x[i], y[i])
		}
		return out
	}
	nones := make([]wire, 32)
	for i := range nones {
		nones[i] = none
	}
	v := make([][]wire, 0, 16)
	for _, word := range h {
		v = append(v, append([]wire(nil), word...))
	}
	for i := range 4 {
		v = append(v, literal(blake2sIV[i]))
	}
	for i, x := range [][]wire{t[:32], t[32:], f0, nones} {
		v = append(v, xor(literal(blake2sIV[4+i]), x))
	}
	for _, sigma := range blake2sSigma {
		for g, lanes := range blake2sLanes {
			a, b, cc, d := lanes[0], lanes[1], lanes[2], lanes[3]
			for _, step := range []struct {
				x      []wire
				r1, r2 int
			}{{m[sigma[2*g]], 16, 12}, {m[sigma[2*g+1]], 8, 7}} {
				v[a] = c.add(c.add(v[a], v[b]), step.x)
				v[d] = rotr(xor(v[d], v[a]), step.r1)
				v[cc] = c.add(v[cc], v[d])
				v[b] = rotr(xor(v[b], v[cc]), step.r2)
			}
		}
	}
	for i := range 8 {
		for bit, w := range xor(xor(h[i], v[i]), v[i+8]) {
			c.output(i/2, 32*(i%2)+bit, w)
		}
	}
	return c
}

var (
	circuitsOnce sync.Once
	circuits     [numTables]*circuit
)

// classCircuits returns the class circuits, built once.
func classCircuits() *[numTables]*circuit {
	circuitsOnce.Do(func() {
		for t, build := range [numTables]func() *gateList{
			aluCircuit, loadCircuit, storeCircuit, shiftCircuit, mulCircuit, mulhCircuit, divCircuit, blake2sCircuit,
		} {
			circuits[t] = build().circuit()
		}
	})
	return &circuits
}
