// Package leanvm verifies leanVM LVMP v1 proofs for the upstream revision in UPSTREAM.md.
// Verify returns the program digest of the supplied ELF after checking its execution output.
package leanvm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

// ProgramDigest returns the digest leanVM identifies the guest elf's program by.
func ProgramDigest(elf []byte) ([32]byte, error) {
	p, err := loadProgram(elf)
	if err != nil {
		return [32]byte{}, err
	}
	return p.digest, nil
}

// Verify checks that proof proves a run of the guest elf that exits with output, four
// little-endian words, and returns the guest's program digest.
func Verify(elf []byte, output [32]byte, proof []byte) ([32]byte, error) {
	wire, err := decodeProof(proof)
	if err != nil {
		return [32]byte{}, err
	}
	p, err := loadProgram(elf)
	if err != nil {
		return [32]byte{}, err
	}
	var words [4]uint64
	for i := range words {
		words[i] = binary.LittleEndian.Uint64(output[8*i:])
	}
	if err := verifyExecution(p, words, wire); err != nil {
		return [32]byte{}, fmt.Errorf("leanvm: the proof does not verify: %w", err)
	}
	return p.digest, nil
}

func loadProgram(elf []byte) (*program, error) {
	g, err := loadGuest(elf)
	if err != nil {
		return nil, err
	}
	return newProgram(g)
}

// stackClaim is a claim on the committed stack: the weight it puts on the stack, as a function of
// the opening's point, and the value it claims.
type stackClaim struct {
	weight func(x []ext) ext
	value  ext
}

// columnClaim is a claim that a committed column's multilinear extension takes value at point.
type columnClaim struct {
	column int
	point  []ext
	value  ext
}

func (c columnClaim) onStack(l *layout) stackClaim {
	point := l.placements[c.column].stackPoint(c.point, l.stackLog)
	return stackClaim{weight: func(x []ext) ext { return eqEval(point, x) }, value: c.value}
}

// verifyExecution verifies that the program, started at its entry on RAM holding its image and
// zeros, with some advice, halts on exit with a0..a3 holding output.
func verifyExecution(p *program, output [4]uint64, proof *wireProof) error {
	tables := classTables()
	t := newTranscript(proof, p.digest, output)

	// The announced table heights, rate, and the clock the run ended on.
	announced, err := t.nextScalars(numTables + 2)
	if err != nil {
		return err
	}
	for _, v := range announced {
		if v.c1 != 0 || v.c2 != 0 {
			return errors.New("an announced value has a nonzero high limb")
		}
	}
	finalClock := announced[numTables+1]
	if finalClock.isZero() {
		return errors.New("the final clock is zero")
	}
	var heights [numTables]int
	for i := range heights {
		if announced[i].c0 > maxLogRows {
			return errors.New("invalid announced table sizes")
		}
		heights[i] = int(announced[i].c0)
	}
	logInvRate := announced[numTables].c0
	if logInvRate < 1 || logInvRate > 4 {
		return errors.New("invalid PCS inverse rate")
	}
	l, ok := buildLayout(p, heights, finalClock)
	if !ok {
		return errors.New("invalid announced sizes")
	}

	root, err := t.nextRoot()
	if err != nil {
		return err
	}

	bus, err := verifyBusBalance(l, t)
	if err != nil {
		return err
	}

	// One batched table sumcheck at the bus point, proving the target the leaf claims derive and
	// that the constraints vanish.
	xi := t.sample()
	nConstraints := 0
	for _, tb := range tables {
		nConstraints += len(tb.slots)
	}
	xiPowers := powers(xi, nConstraints+3)
	constraintPowers, formPowers := xiPowers[:nConstraints], xiPowers[nConstraints:]
	target := dot(formPowers, bus.totals[:])
	tableClaims, err := tableSumcheck(l, bus.forms, constraintPowers, formPowers, bus.point, target, t)
	if err != nil {
		return err
	}
	claims := append(bus.claims, tableClaims...)

	// The exit: a7 holds exit and a0..a3 the output when the run ends.
	exitClaim := func(register int, value uint64) columnClaim {
		return columnClaim{colRegisterFinal, selectorPoint(register, logRegisters), lift(value)}
	}
	claims = append(claims, exitClaim(syscallReg, sysExit))
	for i, r := range outputRegisters {
		claims = append(claims, exitClaim(r, output[i]))
	}

	// Each class's circuit via flock, one reduction per table over its packed witness.
	var families [numTables]flockClaim
	maxGates := 0
	for _, tb := range tables {
		maxGates = max(maxGates, len(tb.circuit.gates))
	}
	wires := make([]ext, maxGates)
	for i, tb := range tables {
		fc, err := verifyFlock(tb.circuit, heights[i], t, wires)
		if err != nil {
			return err
		}
		families[i] = fc
	}

	// Ring switching: each family's claims become one claim on its witness's region of the stack.
	switched := ringSwitch(families[:], t)
	stack := make([]stackClaim, 0, numTables+len(claims))
	for i := range tables {
		region := l.placements[numFramework+i]
		weight := switched[i].weight
		stack = append(stack, stackClaim{
			weight: func(x []ext) ext { return region.eqAbove(x).mul(weight(x[:region.variables])) },
			value:  switched[i].value,
		})
	}
	for _, c := range claims {
		stack = append(stack, c.onStack(l))
	}
	if err := verifyStackedOpening(t, root, l.stackLog, int(logInvRate), l.nLanes, stack); err != nil {
		return err
	}
	return t.finish()
}

// Bus balance ------------------------------------------------------------------------------------

type busResult struct {
	claims []columnClaim
	point  []ext
	forms  [numTables][3]form
	totals [3]ext
}

// verifyGKR replays three batched grand-product GKRs (push, pull, count) of the given depth.
func verifyGKR(depth int, t *transcript) (count ext, point []ext, values [3]ext, err error) {
	shared, err := t.nextScalar()
	if err != nil {
		return
	}
	count, err = t.nextScalar()
	if err != nil {
		return
	}
	combiner := t.sample()
	vals := []ext{shared, shared, count}
	for layer := depth; layer > 0; {
		step := 2
		if layer%2 == 1 {
			step = 1
		}
		claim := polyEval(vals, combiner)
		var x []ext
		x, claim, err = t.sumcheck(claim, 1<<step+1, eqRounds(point))
		if err != nil {
			return
		}
		var children [3][]ext
		products := make([]ext, 3)
		for i := range children {
			children[i], err = t.nextScalars(1 << step)
			if err != nil {
				return
			}
			products[i] = extOne
			for _, v := range children[i] {
				products[i] = products[i].mul(v)
			}
		}
		if claim != polyEval(products, combiner) {
			err = fmt.Errorf("GKR layer %d: children do not match the sumcheck", layer)
			return
		}
		y := t.samples(step)
		for i := range children {
			vals[i] = multilinearEval(children[i], y)
		}
		combiner = t.sample()
		point = append(y, x...)
		layer -= step
	}
	return count, point, [3]ext{vals[0], vals[1], vals[2]}, nil
}

type busLayout struct {
	depth     int
	framework []placement
	tables    []placement
}

func newBusLayout(frameworkLogRows []int, blocks []busBlock) busLayout {
	sizes := append([]int(nil), frameworkLogRows...)
	for _, b := range blocks {
		sizes = append(sizes, b.logRows)
	}
	offsets, total := stackOffsets(sizes)
	placements := make([]placement, len(sizes))
	for i := range sizes {
		placements[i] = placement{sizes[i], offsets[i], 0}
	}
	split := len(frameworkLogRows)
	return busLayout{log2Ceil(total), placements[:split], placements[split:]}
}

func verifyBusBalance(l *layout, t *transcript) (*busResult, error) {
	p := l.prog
	logBC := p.logBytecode()
	frameworkLogRows := []int{0, logRegisters, p.logRAM, p.logAdvice, logBC, rangeLog, rangeLog}
	pushLayout := newBusLayout(frameworkLogRows, l.push)
	pullLayout := newBusLayout(frameworkLogRows, l.pull)
	countLayout := newBusLayout(nil, l.count)

	alphas := t.samples(busBits)
	weights := eqKernel(alphas)
	beta := t.sample()
	countRoot, point, treeValues, err := verifyGKR(pushLayout.depth, t)
	if err != nil {
		return nil, err
	}
	if countRoot.isZero() {
		return nil, errors.New("a bus count is zero")
	}

	// The framework blocks' committed columns, in the order the two sides first name them.
	if len(point) < max(logRegisters, p.logRAM, p.logAdvice, logBC, rangeLog) {
		return nil, errors.New("the bus is smaller than its framework")
	}
	registerLow, ramLow, adviceLow := point[:logRegisters], point[:p.logRAM], point[:p.logAdvice]
	bytecodeLow, rangeLow := point[:logBC], point[:rangeLog]
	scalars, err := t.nextScalars(10)
	if err != nil {
		return nil, err
	}
	adviceInitial, registerFinalTS, registerFinal := scalars[0], scalars[1], scalars[2]
	ramFinalTS, ramFinal, adviceFinalTS, adviceFinal := scalars[3], scalars[4], scalars[5], scalars[6]
	bytecodeFinal, rangeLoFinal, rangeHiFinal := scalars[7], scalars[8], scalars[9]
	res := &busResult{point: point}
	res.claims = []columnClaim{
		{colAdviceInitial, adviceLow, adviceInitial},
		{colRegisterFinalTS, registerLow, registerFinalTS},
		{colRegisterFinal, registerLow, registerFinal},
		{colRAMFinalTS, ramLow, ramFinalTS},
		{colRAMFinal, ramLow, ramFinal},
		{colAdviceFinalTS, adviceLow, adviceFinalTS},
		{colAdviceFinal, adviceLow, adviceFinal},
		{colBytecodeFinal, bytecodeLow, bytecodeFinal},
		{colRangeLoFinal, rangeLow, rangeLoFinal},
		{colRangeHiFinal, rangeLow, rangeHiFinal},
	}
	// Register numbers, addresses and pcs are integers.
	registerIndex := intIndexMLE(0, 0, registerLow)
	ramIndex := intIndexMLE(ramBase, 3, ramLow)
	ramInitial := sparseMLE(0, p.image, ramLow)
	adviceIndex := intIndexMLE(adviceBase, 3, adviceLow)
	bytecodeIndex := intIndexMLE(textBase, 2, bytecodeLow)
	bytecodeValue := p.bytecodeMLE(bytecodeLow, alphas)
	// The range arrays' addresses g^(j+1) and g^(-2^16 j) are geometric.
	rangeLoIndex := powersMLE(extGen, extGen, rangeLow)
	rangeHiIndex := powersMLE(extOne, rangeHiRatio, rangeLow)

	fingerprints := func(pc, clock, exitMarker, registerTS, register, ramTS, ramV, adviceTS, advice, bytecodeCount, rangeLoCount, rangeHiCount ext) []ext {
		w4, w3 := weights[:4], weights[:3]
		return []ext{
			dot(w4, []ext{sepState, pc, clock, exitMarker}),
			dot(w4, []ext{sepReg, registerIndex, registerTS, register}),
			dot(w4, []ext{sepMem, ramIndex, ramTS, ramV}),
			dot(w4, []ext{sepMem, adviceIndex, adviceTS, advice}),
			dot(w3, []ext{sepBytecode, bytecodeIndex, bytecodeCount}).add(bytecodeValue),
			dot(w3, []ext{sepRangeLo, rangeLoIndex, rangeLoCount}),
			dot(w3, []ext{sepRangeHi, rangeHiIndex, rangeHiCount}),
		}
	}
	haltPC := lift(p.haltPC())
	start := fingerprints(lift(p.entryPC), lift(gpow(clockStride)), extZero, extOne, extZero, extOne, ramInitial, extOne, adviceInitial, extOne, extOne, extOne)
	end := fingerprints(haltPC, l.finalClock, l.finalClock, registerFinalTS, registerFinal, ramFinalTS, ramFinal, adviceFinalTS, adviceFinal, bytecodeFinal, rangeLoFinal, rangeHiFinal)

	for i := range res.forms {
		for s := range res.forms[i] {
			res.forms[i][s] = form{}
		}
	}
	sides := []struct {
		blocks       []busBlock
		layout       busLayout
		fingerprints []ext
		weights      []ext
		beta         ext
	}{
		{l.push, pushLayout, start, weights, beta},
		{l.pull, pullLayout, end, weights, beta},
		// The count channel owns no framework block and runs at alpha = beta = 0.
		{l.count, countLayout, nil, []ext{extOne}, extZero},
	}
	for s, side := range sides {
		var known, padding ext
		for i, pl := range side.layout.framework {
			sel := pl.eqAbove(point)
			known = known.add(sel.mul(side.beta.add(side.fingerprints[i])))
			padding = padding.add(sel)
		}
		betaForm := constForm(side.beta)
		for i, pl := range side.layout.tables {
			sel := pl.eqAbove(point)
			padding = padding.add(sel)
			block := side.blocks[i]
			f := res.forms[block.owner][s]
			f.addScaled(betaForm, sel)
			for slot, coordinate := range block.coordinates {
				f.addScaled(coordinate, sel.mul(side.weights[slot]))
			}
		}
		// Every occupied row holds beta plus its fingerprint; the rest of the leaf cube holds 1.
		res.totals[s] = treeValues[s].add(known).add(padding).add(extOne)
	}
	return res, nil
}

// Table sumcheck ---------------------------------------------------------------------------------

func tableSumcheck(l *layout, busForms [numTables][3]form, constraintPowers, formPowers []ext, equalityPoint []ext, target ext, t *transcript) ([]columnClaim, error) {
	tables := classTables()
	nRounds := 0
	for _, h := range l.tableHeights {
		nRounds = max(nRounds, h)
	}
	if len(equalityPoint) < nRounds {
		return nil, errors.New("the bus point is shorter than a table")
	}
	challenges, claim, err := t.sumcheck(target, 4, plainRounds(nRounds))
	if err != nil {
		return nil, err
	}
	point := make([]ext, nRounds)
	for i := range point {
		point[i] = challenges[nRounds-1-i]
	}
	var weights [numTables]ext
	for i := range weights {
		weights[i] = extOne
	}
	for v, c := range point {
		equality := extOne.add(equalityPoint[v]).add(c)
		for i, h := range l.tableHeights {
			if h > v {
				weights[i] = weights[i].mul(equality)
			} else {
				weights[i] = weights[i].mul(c)
			}
		}
	}

	var final ext
	cursor := 0
	var claims []columnClaim
	for i, tb := range tables {
		evaluations, err := t.nextScalars(tb.width())
		if err != nil {
			return nil, err
		}
		n := len(tb.slots)
		summand := dot(constraintPowers[cursor:cursor+n], tb.constraints(evaluations))
		var bus ext
		for s := range 3 {
			bus = bus.add(formPowers[s].mul(busForms[i][s].evaluate(evaluations)))
		}
		final = final.add(weights[i].mul(summand.add(bus)))
		cursor += n
		tablePoint := point[:l.tableHeights[i]]
		for local, v := range evaluations {
			claims = append(claims, columnClaim{globalBases[i] + local, tablePoint, v})
		}
	}
	if final != claim {
		return nil, errors.New("table sumcheck terminal mismatch")
	}
	return claims, nil
}

// Flock reduction --------------------------------------------------------------------------------

var (
	// phiBasis spans the univariate skip's evaluation domain, phi[i] the sum of the basis elements
	// the bits of i select.
	phiBasis = [8]uint64{0x0000000000000001, 0x033CE8BEDDC8A656, 0x512620375ED2A108, 0x0C9E636090AAFC01, 0xBA4F3CD82801769C, 0xBA26E7904ADB4A47, 0x467698598926DC01, 0x4418AE808B28BDD0}
	phi      [256]ext
	// fixedChallenges are the zerocheck point's seven fixed coordinates.
	fixedChallenges []ext
	// windowDenominators[k] inverts prod_{0 < j < 2^k} phi[j].
	windowDenominators = map[int]ext{}
)

func init() {
	for v := range phi {
		var acc uint64
		for bit := range 8 {
			if v>>bit&1 == 1 {
				acc ^= phiBasis[bit]
			}
		}
		phi[v] = lift(acc)
	}
	medium := ext{0x243F6A8885A308D3, 0x13198A2E03707344, 0xA4093822299F31D0}
	fixedChallenges = []ext{phi[0xF7], phi[0x53], phi[0xB5]}
	for power := range 4 {
		m := medium.frobenius(power)
		fixedChallenges = append(fixedChallenges, m.mul(extOne.add(m).inv()))
	}
	for _, count := range []int{kBits, 2 * kBits} {
		prod := extOne
		for _, v := range phi[1:count] {
			prod = prod.mul(v)
		}
		windowDenominators[count] = prod.inv()
	}
}

// lagrangeWeights are the barycentric weights of phi[:count] at point.
func lagrangeWeights(count int, point ext) []ext {
	differences := make([]ext, count)
	for i := range differences {
		differences[i] = point.add(phi[i])
	}
	prefix := make([]ext, count+1)
	prefix[0] = extOne
	for i, d := range differences {
		prefix[i+1] = prefix[i].mul(d)
	}
	suffix := make([]ext, count+1)
	suffix[count] = extOne
	for i := count - 1; i >= 0; i-- {
		suffix[i] = suffix[i+1].mul(differences[i])
	}
	den, ok := windowDenominators[count]
	if !ok {
		panic("leanvm: unsupported internal interpolation window")
	}
	out := make([]ext, count)
	for i := range out {
		out[i] = prefix[i].mul(suffix[i+1]).mul(den)
	}
	return out
}

// flockClaim is what a flock reduction leaves: a point and the 64 claims s[i] = z(i, point).
type flockClaim struct {
	point []ext
	s     []ext
}

func verifyFlock(c *circuit, logHeight int, t *transcript, wires []ext) (flockClaim, error) {
	// The zerocheck: one univariate skip round, then quadratic ones.
	logN := c.logSize + logHeight
	r := append(append([]ext(nil), fixedChallenges...), t.samples(logN-flockKSkip-len(fixedChallenges))...)
	pCoset, err := t.nextScalars(kBits)
	if err != nil {
		return flockClaim{}, err
	}
	zSkip := t.sample()
	values := append(make([]ext, kBits), pCoset...)
	vP := dot(lagrangeWeights(2*kBits, zSkip), values)
	chi, running, err := t.sumcheck(vP, 3, eqRounds(r))
	if err != nil {
		return flockClaim{}, err
	}
	ab, err := t.nextScalars(2)
	if err != nil {
		return flockClaim{}, err
	}
	vA, vB := ab[0], ab[1]
	vC := running.add(vA.mul(vB))

	// The lincheck at (z_skip, chi).
	nRounds := c.logSize - flockKSkip
	alpha := t.sample()
	skipWeights := lagrangeWeights(kBits, zSkip)
	chiIn := chi[:nRounds]
	eqIn := eqKernel(chiIn)
	alpha2 := alpha.square()
	alpha3 := alpha2.mul(alpha)
	claim := vA.add(alpha.mul(vB)).add(alpha2.mul(vC)).add(alpha3)
	roundChallenges, rLC, err := t.sumcheck(claim, 3, plainRounds(nRounds))
	if err != nil {
		return flockClaim{}, err
	}
	s, err := t.nextScalars(kBits)
	if err != nil {
		return flockClaim{}, err
	}
	chiInPrime := make([]ext, nRounds)
	for i := range chiInPrime {
		chiInPrime[i] = roundChallenges[nRounds-1-i]
	}
	eqPrime := eqKernel(chiInPrime)
	constantColumn := eqPrime[c.constantColumn/kBits].mul(s[c.constantColumn%kBits])
	terminal := c.bilinearScratch(alpha, eqIn, skipWeights, eqPrime, s, wires).
		add(alpha2.mul(eqEval(chiIn, chiInPrime)).mul(dot(skipWeights, s))).
		add(alpha3.mul(constantColumn))
	if terminal != rLC {
		return flockClaim{}, errors.New("flock lincheck terminal mismatch")
	}
	return flockClaim{point: append(chiInPrime, chi[nRounds:]...), s: s}, nil
}

// Ring switching ---------------------------------------------------------------------------------

// ringMapShifts are the Frobenius shifts of the six stages composing the map, one challenge each.
var ringMapShifts = []int{32, 16, 8, 4, 2, 1}

type switchedClaim struct {
	value  ext
	weight func(rPrime []ext) ext
}

// ringSwitch turns each family of 64 claims s[i] = z(i, point) into one claim
// sum_u W(u) q(u) = T on its packed witness, with T = sum_i g^i Phi(s_i) and W(u) = Phi(eq(point, u)).
func ringSwitch(families []flockClaim, t *transcript) []switchedClaim {
	challenges := t.samples(len(ringMapShifts))
	// The map as a Frobenius sum, Phi(a) = sum_k c_k a^(2^k) for k < 64.
	coefficients := make([]ext, kBits)
	for k := range coefficients {
		c := extOne
		for i, shift := range ringMapShifts {
			if k&shift != 0 {
				c = c.mul(challenges[i].frobenius(k % shift))
			}
		}
		coefficients[k] = c
	}
	phiMap := func(v ext) ext {
		for i, shift := range ringMapShifts {
			v = v.add(challenges[i].mul(v.frobenius(shift)))
		}
		return v
	}
	out := make([]switchedClaim, len(families))
	for i, f := range families {
		mapped := make([]ext, len(f.s))
		for j, v := range f.s {
			mapped[j] = phiMap(v)
		}
		point := f.point
		out[i] = switchedClaim{
			value: polyEval(mapped, extGen),
			weight: func(rPrime []ext) ext {
				var total ext
				frob := append([]ext(nil), point...)
				for _, c := range coefficients {
					product := c
					for n, v := range frob {
						product = product.mul(extOne.add(v).add(rPrime[n]))
					}
					total = total.add(product)
					for n := range frob {
						frob[n] = frob[n].square()
					}
				}
				return total
			},
		}
	}
	return out
}

// Stacked opening and WHIR ---------------------------------------------------------------------

// verifyStackedOpening discharges every claim on the committed stack in one WHIR opening: powers of
// one challenge batch the values into the target and the weights into the basis WHIR evaluates at
// its terminal point.
func verifyStackedOpening(t *transcript, root [32]byte, stackLog, logInvRate, nLanes int, claims []stackClaim) error {
	scales := powers(t.sample(), len(claims))
	var target ext
	for i, c := range claims {
		target = target.add(scales[i].mul(c.value))
	}
	basis := func(point []ext) ext {
		var out ext
		for i, c := range claims {
			out = out.add(scales[i].mul(c.weight(point)))
		}
		return out
	}
	return verifyWhir(t, stackLog, logInvRate, nLanes, target, root, basis)
}

const (
	initialFoldingFactor    = 6
	subsequentFoldingFactor = 4
	rsInitialReduction      = 3
	rsSubsequentReduction   = 1
	residualMaxLog          = 5
)

// whirQueries are the tabulated query counts, by rate and stacked size.
var whirQueries = [4][14][]int{
	{{223, 55}, {223, 56, 30}, {223, 56, 31}, {224, 56, 32}, {224, 56, 32}, {224, 56, 32, 22}, {224, 56, 32, 22}, {225, 56, 32, 23}, {225, 56, 32, 23}, {225, 56, 32, 23, 17}, {226, 56, 32, 23, 17}, {226, 56, 32, 23, 18}, {227, 56, 32, 23, 18}, {228, 56, 32, 23, 18, 14}},
	{{112, 45}, {112, 45, 27}, {112, 45, 28}, {112, 45, 28}, {112, 45, 28}, {112, 45, 28, 20}, {112, 45, 28, 20}, {112, 45, 28, 21}, {112, 45, 28, 21}, {113, 45, 28, 21, 16}, {113, 45, 28, 21, 16}, {113, 45, 28, 21, 16}, {113, 45, 28, 21, 16}, {113, 45, 28, 21, 17, 13}},
	{{75, 37}, {75, 37, 24}, {75, 38, 25}, {75, 38, 25}, {75, 38, 25}, {75, 38, 25, 18}, {75, 38, 25, 19}, {75, 38, 25, 19}, {75, 38, 25, 19}, {75, 38, 25, 19, 15}, {75, 38, 25, 19, 15}, {75, 38, 25, 19, 15}, {75, 38, 25, 19, 15}, {76, 38, 25, 19, 16, 13}},
	{{56, 32}, {56, 32, 22}, {56, 32, 22}, {56, 32, 23}, {56, 32, 23}, {56, 32, 23, 17}, {56, 32, 23, 17}, {56, 32, 23, 18}, {56, 32, 23, 18}, {57, 32, 23, 18, 14}, {57, 32, 23, 18, 14}, {57, 32, 23, 18, 15}, {57, 33, 23, 18, 15}, {57, 33, 23, 18, 15, 12}},
}

type whirConfig struct {
	logInvRates []int
	folds       []int
	queries     []int
}

func deriveConfig(logN, logInvRate int) (whirConfig, error) {
	if logN < minStackedLog || logN > maxStackedLog || logInvRate < 1 || logInvRate > 4 {
		return whirConfig{}, errors.New("invalid WHIR shape")
	}
	cfg := whirConfig{logInvRates: []int{logInvRate}, folds: []int{initialFoldingFactor}}
	remaining := logN - initialFoldingFactor
	for remaining > residualMaxLog {
		reduction := rsSubsequentReduction
		if len(cfg.folds) == 1 {
			reduction = rsInitialReduction
		}
		cfg.logInvRates = append(cfg.logInvRates, cfg.logInvRates[len(cfg.logInvRates)-1]+cfg.folds[len(cfg.folds)-1]-reduction)
		fold := min(subsequentFoldingFactor, remaining)
		remaining -= fold
		cfg.folds = append(cfg.folds, fold)
	}
	cfg.queries = whirQueries[logInvRate-1][logN-minStackedLog]
	if len(cfg.queries) != len(cfg.folds) {
		return whirConfig{}, errors.New("tabulated query count does not match the ladder")
	}
	return cfg, nil
}

// sampleQueries draws count positions in a block of 2^depth: each challenge yields 192/depth
// disjoint depth-bit chunks, low bits first.
func sampleQueries(t *transcript, blockLength, count int) []int {
	depth := bitLen(uint64(blockLength)) - 1
	perWord := 192 / depth
	out := make([]int, 0, count)
	for len(out) < count {
		v := t.sample()
		limbs := [3]uint64{v.c0, v.c1, v.c2}
		for j := range min(perWord, count-len(out)) {
			off := j * depth
			li, sh := off/64, off%64
			chunk := limbs[li] >> sh
			if sh+depth > 64 {
				chunk |= limbs[li+1] << (64 - sh)
			}
			out = append(out, int(chunk&uint64(blockLength-1)))
		}
	}
	return out
}

func subspaceRoots(logN int) []ext {
	roots := []ext{extOne}
	layer := make([]ext, logN)
	for i := range layer {
		layer[i] = lift(uint64(1) << (i + 1))
	}
	for range logN {
		last := roots[len(roots)-1]
		for i, v := range layer {
			layer[i] = v.square().add(last.mul(v))
		}
		roots = append(roots, layer[0])
		layer = layer[1:]
	}
	return roots
}

type inducedBasis struct{ roots, inverses []ext }

// The WHIR configuration bounds the cache dimensions.
var inducedBases = func() (cache [maxStackedLog + 1]func() inducedBasis) {
	for log := range cache {
		cache[log] = sync.OnceValue(func() inducedBasis {
			roots := subspaceRoots(log)
			inverses := make([]ext, len(roots))
			for i, v := range roots {
				if !v.isZero() {
					inverses[i] = v.inv()
				}
			}
			return inducedBasis{roots, inverses}
		})
	}
	return
}()

// inducedWeight is a level's batched query claims as one weight at point: each query contributes
// prod_k (1 + p_k (1 + W_k(x_q) / W_k(v_k))), scaled by its power of the level's batching
// challenge.
func inducedWeight(messageLog int, queries []int, queryWeights []ext, point []ext) ext {
	if len(point) != messageLog {
		panic("leanvm: bad induced-basis dimensions")
	}
	basisData := inducedBases[messageLog]()
	roots, inverses := basisData.roots, basisData.inverses
	var total ext
	for i, q := range queries {
		basis := lift(uint64(q))
		product := queryWeights[i]
		for k, c := range point {
			product = product.mul(extOne.add(c.mul(extOne.add(basis.mul(inverses[k])))))
			basis = basis.square().add(roots[k].mul(basis))
		}
		total = total.add(product)
	}
	return total
}

type gluedClaim struct {
	scalar    ext
	foldStart int
	weightAt  func(x []ext) ext
}

// verifyWhir verifies the base-field multilevel opening with a one-point terminal check.
func verifyWhir(t *transcript, logN, logInvRate, nLanes int, target ext, root [32]byte, evaluateBasis func([]ext) ext) error {
	cfg, err := deriveConfig(logN, logInvRate)
	if err != nil {
		return err
	}
	levels := len(cfg.folds)
	runningQuad, err := t.roundPoly(3, target, nil)
	if err != nil {
		return err
	}
	var folds []ext
	var glued []gluedClaim
	currentRoot := root
	for level := range levels {
		foldCount, levelRate := cfg.folds[level], cfg.logInvRates[level]
		levelFolds := make([]ext, 0, foldCount)
		for range foldCount {
			c := t.sample()
			folds = append(folds, c)
			levelFolds = append(levelFolds, c)
			if runningQuad, err = t.roundPoly(3, polyEval(runningQuad, c), nil); err != nil {
				return err
			}
		}
		messageLog := logN - len(folds)
		finalLevel := level == levels-1

		type pendingClaim struct {
			intro    []ext
			weightAt func(x []ext) ext
		}
		var pending []pendingClaim
		var residual []ext
		var nextRoot [32]byte
		if finalLevel {
			if residual, err = t.nextScalars(1 << messageLog); err != nil {
				return err
			}
		} else {
			if nextRoot, err = t.nextRoot(); err != nil {
				return err
			}
			oodPoint := t.samples(messageLog)
			oodValue, err := t.nextScalar()
			if err != nil {
				return err
			}
			intro, err := t.roundPoly(3, oodValue, nil)
			if err != nil {
				return err
			}
			pending = append(pending, pendingClaim{intro, func(x []ext) ext { return eqEval(oodPoint, x) }})
		}

		if err := t.grindCheck(queryGrindingBits); err != nil {
			return err
		}
		blockLength := 1 << (messageLog + levelRate)
		queries := sampleQueries(t, blockLength, cfg.queries[level])
		lam := t.sample()
		queryWeights := powers(lam, len(queries))
		// Level 0 committed the K witness, one leaf word per lane, the absent lanes a zero prefix of
		// the leaf image; every deeper level a folded E one, three words per lane.
		lanes := 1 << foldCount
		laneWeights := eqKernel(levelFolds)
		var enforced ext
		if level == 0 {
			rows, err := t.merkle(currentRoot, blockLength, queries, nLanes, lanes)
			if err != nil {
				return err
			}
			for i, row := range rows {
				// The image is lane-descending.
				var acc ext
				for j, w := range row {
					acc = acc.add(laneWeights[lanes-1-j].mulK(w))
				}
				enforced = enforced.add(queryWeights[i].mul(acc))
			}
		} else {
			rows, err := t.merkle(currentRoot, blockLength, queries, 3*lanes, 3*lanes)
			if err != nil {
				return err
			}
			for i, row := range rows {
				var acc ext
				for j := range lanes {
					acc = acc.add(laneWeights[j].mul(ext{row[3*j], row[3*j+1], row[3*j+2]}))
				}
				enforced = enforced.add(queryWeights[i].mul(acc))
			}
		}
		intro, err := t.roundPoly(3, enforced, nil)
		if err != nil {
			return err
		}
		pending = append(pending, pendingClaim{intro, func(x []ext) ext {
			return inducedWeight(messageLog, queries, queryWeights, x)
		}})
		scalar := extOne
		for _, pc := range pending {
			scalar = scalar.mul(lam)
			for i := range runningQuad {
				runningQuad[i] = runningQuad[i].add(scalar.mul(pc.intro[i]))
			}
			glued = append(glued, gluedClaim{scalar, len(folds), pc.weightAt})
		}

		if finalLevel {
			tailFolds := make([]ext, 0, messageLog)
			var runningTarget ext
			for round := range messageLog {
				c := t.sample()
				runningTarget = polyEval(runningQuad, c)
				tailFolds = append(tailFolds, c)
				if round+1 < messageLog {
					if runningQuad, err = t.roundPoly(3, runningTarget, nil); err != nil {
						return err
					}
				}
			}
			point := append(append([]ext(nil), folds...), tailFolds...)
			laneFolds := cfg.folds[0]
			weight := evaluateBasis(append(append([]ext(nil), point[laneFolds:]...), point[:laneFolds]...))
			for _, g := range glued {
				x := append(append([]ext(nil), folds[g.foldStart:]...), tailFolds...)
				weight = weight.add(g.scalar.mul(g.weightAt(x)))
			}
			if weight.mul(multilinearEval(residual, tailFolds)) != runningTarget {
				return errors.New("WHIR terminal check failed")
			}
			return nil
		}
		currentRoot = nextRoot
	}
	return errors.New("WHIR verification ended without a terminal level")
}
