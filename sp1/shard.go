package sp1

import (
	"errors"
	"fmt"
	"math/bits"
	"slices"
)

var (
	errInvalidShape        = errors.New("invalid shape of proof")
	errInvalidPublicValues = errors.New("public values verification failed")
)

// log2Ceil returns the smallest k with 2^k >= n (0 for n <= 1).
func log2Ceil(n uint64) int {
	if n <= 1 {
		return 0
	}
	return bits.Len64(n - 1)
}

// shardChip pairs a chip of the machine with its openings in the proof.
type shardChip struct {
	air     *chipAir
	opening *chipOpening
	gkr     *chipEvaluation
}

// verifyShard checks a compress shard proof, after the verifying key was observed into c.
func verifyShard(vk *verifyingKey, p *shardProof, c *challenger) error {
	if len(p.publicValues) != numPublicValues {
		return errInvalidPublicValues
	}

	c.observeFelts(p.publicValues)
	c.observeDigest(p.mainCommitment)
	c.observe(feltFromU64(uint64(len(p.openings))))
	for _, o := range p.openings {
		degree := o.value.degree
		if len(degree) != maxLogRowCount+1 || len(degree) >= 30 {
			return errInvalidShape
		}
		height := bitStringEvaluation(degree)
		c.observe(height)
		c.observe(feltFromU64(uint64(len(o.name))))
		for _, b := range []byte(o.name) {
			c.observe(felt(b))
		}
	}

	pcs := &p.pcs
	if len(pcs.rowColCounts) != 2 {
		return errInvalidShape
	}
	// The proof must open exactly the machine's chips (its only chip cluster), so every chip with a
	// preprocessed trace appears, and the preprocessed column counts must be the machine's.
	if len(p.openings) != len(compressChips) {
		return errInvalidShape
	}
	var preprocessedWidths []uint64
	for i := range compressChips {
		if p.openings[i].name != compressChips[i].name {
			return errInvalidShape
		}
		if w := compressChips[i].preprocessedWidth; w != 0 {
			preprocessedWidths = append(preprocessedWidths, uint64(w))
		}
	}
	if len(pcs.rowColCounts[0]) < len(preprocessedWidths) {
		return errInvalidShape
	}
	for i, w := range preprocessedWidths {
		if pcs.rowColCounts[0][i][1] != w {
			return errInvalidShape
		}
	}

	if len(p.gkr.chipEvals) != len(compressChips) {
		return errInvalidShape
	}
	chips := make([]shardChip, len(compressChips))
	for i := range compressChips {
		air, eval := &compressChips[i], &p.gkr.chipEvals[i]
		if eval.name != air.name {
			return fmt.Errorf("invalid chip opening order: (%s, %s)", air.name, eval.name)
		}
		if numEvaluations(eval.value.preprocessed) != air.preprocessedWidth ||
			len(eval.value.main.data) != air.width {
			return errInvalidShape
		}
		chips[i] = shardChip{air: air, opening: &p.openings[i].value, gkr: &eval.value}
	}

	if err := verifyGkr(chips, &p.gkr, c); err != nil {
		return fmt.Errorf("GKR verification failed: %w", err)
	}
	if err := verifyZerocheck(chips, p, c); err != nil {
		return err
	}

	var preprocessedOpenings, mainOpenings []ext
	for _, ch := range chips {
		preprocessedOpenings = append(preprocessedOpenings, ch.opening.preprocessed...)
		mainOpenings = append(mainOpenings, ch.opening.main...)
	}
	commitments := []digest{vk.preprocessedCommit, p.mainCommitment}
	claims := [][]ext{preprocessedOpenings, mainOpenings}
	if err := verifyJagged(commitments, p.zerocheck.point, claims, pcs, c); err != nil {
		return fmt.Errorf("invalid pcs opening proof: %w", err)
	}

	// The jagged proof's row counts, less its two padding tables, must be the chips' heights, and
	// its column counts the chips' widths.
	var wantRows [2][]uint64
	var wantCols [2][]uint64
	for _, ch := range chips {
		height := uint64(bitStringEvaluation(ch.opening.degree))
		if ch.air.preprocessedWidth > 0 {
			wantRows[0] = append(wantRows[0], height)
			wantCols[0] = append(wantCols[0], uint64(ch.air.preprocessedWidth))
		}
		wantRows[1] = append(wantRows[1], height)
		wantCols[1] = append(wantCols[1], uint64(ch.air.width))
	}
	for round, counts := range pcs.rowColCounts {
		// verifyJagged checked that every round has its two padding tables.
		realCounts := counts[:len(counts)-2]
		if len(realCounts) != len(wantRows[round]) {
			return errInvalidShape
		}
		for i, rc := range realCounts {
			if rc[0] != wantRows[round][i] || rc[1] != wantCols[round][i] {
				return errInvalidShape
			}
		}
	}
	return nil
}

// bitStringEvaluation reads a height from its bits, most significant first, in the field.
func bitStringEvaluation(bits []felt) felt {
	var acc felt
	for _, x := range bits {
		acc = acc.add(acc).add(x)
	}
	return acc
}

func numEvaluations(t *tensor[ext]) int {
	if t == nil {
		return 0
	}
	return len(t.data)
}

// verifyGkr checks the LogUp-GKR proof that the chips' interactions balance, reducing it to claims
// about the chips' trace evaluations at the proof's point.
func verifyGkr(chips []shardChip, g *gkrProof, c *challenger) error {
	maxArity, numInteractions := 1, 0
	for _, ch := range chips {
		for _, in := range ch.air.sends {
			maxArity = max(maxArity, len(in.values)+1)
		}
		for _, in := range ch.air.receives {
			maxArity = max(maxArity, len(in.values)+1)
		}
		numInteractions += ch.air.numInteractions()
	}
	if numInteractions == 0 {
		return errInvalidShape
	}
	betaSeedDim := log2Ceil(uint64(maxArity))

	if !c.checkWitness(gkrGrindingBits, g.witness) {
		return errors.New("invalid proof of work witness")
	}
	alpha := c.sampleExt()
	betaSeed := c.samplePoint(betaSeedDim)
	// The public values challenge. The recursion machine has no public value interactions, so
	// their cumulative sum is zero.
	c.sampleExt()

	interactionVars := log2Ceil(uint64(numInteractions))
	expectedSize := uint64(1) << (interactionVars + 1)
	if !g.numerator.isShape(expectedSize, 1) || !g.denominator.isShape(expectedSize, 1) {
		return errInvalidShape
	}
	c.observeExtsWithLength(g.numerator.data)
	c.observeExtsWithLength(g.denominator.data)
	numerator, denominator := extZero, extOne
	for i, d := range g.denominator.data {
		if d.isZero() {
			return errors.New("denominator evaluation has zero value")
		}
		numerator = numerator.mul(d).add(g.numerator.data[i].mul(denominator))
		denominator = denominator.mul(d)
	}
	if !numerator.isZero() {
		return errors.New("cumulative sum mismatch")
	}

	evalPoint := c.samplePoint(interactionVars + 1)
	numeratorEval := mleEval(g.numerator.data, evalPoint)
	denominatorEval := mleEval(g.denominator.data, evalPoint)
	if len(g.rounds)+1 != maxLogRowCount {
		return errInvalidShape
	}
	for i := range g.rounds {
		r := &g.rounds[i]
		lambda := c.sampleExt()
		if r.sumcheck.claimedSum != numeratorEval.mul(lambda).add(denominatorEval) {
			return fmt.Errorf("inconsistent sumcheck claim at round %d", i)
		}
		if err := verifySumcheck(&r.sumcheck, c, i+interactionVars+1, 3); err != nil {
			return err
		}
		eq := fullLagrangeEval(r.sumcheck.point, evalPoint)
		numerator := r.numerator0.mul(r.denominator1).add(r.numerator1.mul(r.denominator0))
		denominator := r.denominator0.mul(r.denominator1)
		if r.sumcheck.eval != eq.mul(numerator.mul(lambda).add(denominator)) {
			return fmt.Errorf("inconsistent evaluation at round %d", i)
		}
		c.observeExt(r.numerator0)
		c.observeExt(r.numerator1)
		c.observeExt(r.denominator0)
		c.observeExt(r.denominator1)
		last := c.sampleExt()
		evalPoint = append(append([]ext{}, r.sumcheck.point...), last)
		numeratorEval = r.numerator0.add(r.numerator1.sub(r.numerator0).mul(last))
		denominatorEval = r.denominator0.add(r.denominator1.sub(r.denominator0).mul(last))
	}

	interactionPoint, tracePoint := evalPoint[:interactionVars], evalPoint[interactionVars:]
	if len(tracePoint) != maxLogRowCount {
		return errInvalidShape
	}
	if !slices.Equal(g.point, tracePoint) {
		return errors.New("trace point mismatch")
	}

	betas := partialLagrange(betaSeed)
	pointExtended := append([]ext{extZero}, g.point...)
	numerators := make([]ext, 0, 1<<interactionVars)
	denominators := make([]ext, 0, 1<<interactionVars)
	c.observe(feltFromU64(uint64(len(chips))))
	for _, ch := range chips {
		var preprocessed []ext
		if ch.gkr.preprocessed != nil {
			c.observeExtsWithLength(ch.gkr.preprocessed.data)
			if !ch.gkr.preprocessed.isShape(uint64(ch.air.preprocessedWidth)) {
				return errInvalidShape
			}
			preprocessed = ch.gkr.preprocessed.data
		} else if ch.air.preprocessedWidth != 0 {
			return errInvalidShape
		}
		c.observeExtsWithLength(ch.gkr.main.data)
		if !ch.gkr.main.isShape(uint64(ch.air.width)) {
			return errInvalidShape
		}
		main := ch.gkr.main.data
		if len(ch.opening.degree) != len(pointExtended) {
			return errInvalidShape
		}
		geq := fullGeq(feltsToExts(ch.opening.degree), pointExtended)
		zeroPreprocessed := make([]ext, len(preprocessed))
		zeroMain := make([]ext, len(main))
		add := func(in interaction, send bool) {
			realNumerator, realDenominator := in.eval(preprocessed, main, alpha, betas)
			padNumerator, padDenominator := in.eval(zeroPreprocessed, zeroMain, alpha, betas)
			numerator := realNumerator.sub(padNumerator.mul(geq))
			if !send {
				numerator = numerator.neg()
			}
			numerators = append(numerators, numerator)
			denominators = append(denominators, realDenominator.add(extOne.sub(padDenominator).mul(geq)))
		}
		for _, in := range ch.air.sends {
			add(in, true)
		}
		for _, in := range ch.air.receives {
			add(in, false)
		}
	}
	for len(numerators) < 1<<interactionVars {
		numerators = append(numerators, extZero)
		denominators = append(denominators, extOne)
	}
	if numeratorEval != mleEval(numerators, interactionPoint) {
		return errors.New("numerator evaluation mismatch")
	}
	if denominatorEval != mleEval(denominators, interactionPoint) {
		return errors.New("denominator evaluation mismatch")
	}
	return nil
}

// verifyZerocheck checks that the chips' constraints vanish on their traces, given the GKR's
// trace evaluation claims, and observes the zerocheck openings.
func verifyZerocheck(chips []shardChip, p *shardProof, c *challenger) error {
	alpha := c.sampleExt()
	batchChallenge := c.sampleExt()
	lambda := c.sampleExt()

	z := &p.zerocheck
	if len(p.gkr.point) != maxLogRowCount || len(z.point) != maxLogRowCount {
		return errInvalidShape
	}
	eq := fullLagrangeEval(p.gkr.point, z.point)
	pointExtended := append([]ext{extZero}, z.point...)

	rlc := extZero
	for _, ch := range chips {
		o := ch.opening
		if len(o.preprocessed) != ch.air.preprocessedWidth {
			return fmt.Errorf("opening shape mismatch: preprocessed width mismatch: %d != %d", ch.air.preprocessedWidth, len(o.preprocessed))
		}
		if len(o.main) != ch.air.width {
			return fmt.Errorf("opening shape mismatch: main width mismatch: %d != %d", ch.air.width, len(o.main))
		}
		for _, x := range o.degree {
			if x.mul(x.sub(1)) != 0 {
				return errors.New("invalid height bit decomposition")
			}
		}
		for _, x := range o.degree[1:] {
			if x.mul(o.degree[0]) != 0 {
				return errors.New("height is larger than maximum possible value")
			}
		}
		geq := fullGeq(feltsToExts(o.degree), pointExtended)
		padding := ch.air.evalConstraints(make([]ext, ch.air.preprocessedWidth), make([]ext, ch.air.width), alpha, p.publicValues)
		constraints := ch.air.evalConstraints(o.preprocessed, o.main, alpha, p.publicValues).sub(padding.mul(geq))
		batch := batchOpenings(batchChallenge, o.main, o.preprocessed)
		rlc = rlc.mul(lambda).add(eq.mul(constraints.add(batch)))
	}
	if z.eval != rlc {
		return fmt.Errorf("constraints check failed: %w", errSumcheckEvaluation)
	}

	modification := extZero
	for _, ch := range chips {
		var preprocessed []ext
		if ch.gkr.preprocessed != nil {
			preprocessed = ch.gkr.preprocessed.data
		}
		modification = lambda.mul(modification).add(batchOpenings(batchChallenge, ch.gkr.main.data, preprocessed))
	}
	if z.claimedSum != modification {
		return fmt.Errorf("constraints check failed: %w", errSumcheckClaimedSum)
	}
	if err := verifySumcheck(z, c, maxLogRowCount, maxConstraintDeg+1); err != nil {
		return fmt.Errorf("constraints check failed: %w", err)
	}

	c.observe(feltFromU64(uint64(len(chips))))
	for _, ch := range chips {
		c.observeExtsWithLength(ch.opening.preprocessed)
		c.observeExtsWithLength(ch.opening.main)
	}
	return nil
}

// batchOpenings returns sum_k v_k * challenge^(k+1) over the main values followed by the
// preprocessed values.
func batchOpenings(challenge ext, main, preprocessed []ext) ext {
	sum, power := extZero, challenge
	for _, values := range [][]ext{main, preprocessed} {
		for _, v := range values {
			sum = sum.add(v.mul(power))
			power = power.mul(challenge)
		}
	}
	return sum
}
