package sp1

import (
	"errors"
	"fmt"
	"math/bits"
	"runtime"
)

var (
	errStackedShape     = errors.New("proof has incorrect shape")
	errBasefoldShape    = errors.New("incorrect shape of proof")
	errBasefoldSumcheck = errors.New("sumcheck error")
	errMerkleShape      = errors.New("proof has incorrect shape")
	errMerkleRoot       = errors.New("root mismatch")
	errMerkleOverflow   = errors.New("base field overflow")
	errMerkleCommitted  = errors.New("width or height inconsistent with commitment")
)

// verifyStacked checks the stacked PCS: the claimed evaluation at point is the batch evaluations'
// multilinear extension at point's leading coordinates, and the batch evaluations are the committed
// columns' evaluations at its trailing logStackingHeight coordinates.
func verifyStacked(commitments []digest, roundAreas []uint64, point []ext, p *stackedProof, claim ext, c *challenger) error {
	if len(point) < logStackingHeight {
		return errStackedShape
	}
	batchPoint, stackPoint := point[:len(point)-logStackingHeight], point[len(point)-logStackingHeight:]
	if len(p.batchEvals) != len(roundAreas) || len(commitments) != len(roundAreas) || len(commitments) != numCommitments {
		return errStackedShape
	}
	var flat []ext
	for round, area := range roundAreas {
		if area%(1<<logStackingHeight) != 0 || area>>logStackingHeight != uint64(len(p.batchEvals[round].data)) {
			return errStackedShape
		}
		flat = append(flat, p.batchEvals[round].data...)
	}
	if mleEval(flat, batchPoint) != claim {
		return errors.New("batch evaluations do not match the claimed evaluations")
	}

	claims := make([][]ext, len(p.batchEvals))
	for round := range p.batchEvals {
		claims[round] = p.batchEvals[round].data
		c.observeExts(claims[round])
	}
	if err := verifyBasefold(commitments, stackPoint, claims, &p.basefold, c); err != nil {
		return fmt.Errorf("PCS error: %w", err)
	}
	return nil
}

// verifyBasefold checks a Basefold opening of the committed rounds' columns at point.
func verifyBasefold(commitments []digest, point []ext, claims [][]ext, p *basefoldProof, c *challenger) error {
	if len(claims) != len(commitments) || len(commitments) != len(p.componentOpenings) || len(commitments) != numCommitments {
		return errBasefoldShape
	}
	if !c.checkWitness(batchGrindingBits, p.batchWitness) {
		return errors.New("invalid batch grinding witness")
	}
	totalLen := 0
	for _, round := range claims {
		totalLen += len(round)
	}
	batchingPoint := c.samplePoint(log2Ceil(uint64(max(totalLen, 1))))
	coefficients := partialLagrange(batchingPoint)
	evalClaim := extZero
	k := 0
	for _, round := range claims {
		for _, v := range round {
			if k < len(coefficients) {
				evalClaim = evalClaim.add(v.mul(coefficients[k]))
			}
			k++
		}
	}

	if len(p.friCommitments) != len(p.univariate) || len(p.friCommitments) != len(point) || len(p.univariate) == 0 {
		return errors.New("sumcheck and FRI commitments length mismatch")
	}
	reversed := make([]ext, len(point))
	for i := range point {
		reversed[i] = point[len(point)-1-i]
	}

	c.observe(feltFromU64(uint64(len(p.friCommitments))))
	betas := make([]ext, len(p.friCommitments))
	for i, commitment := range p.friCommitments {
		c.observeExt(p.univariate[i][0])
		c.observeExt(p.univariate[i][1])
		c.observeDigest(commitment)
		betas[i] = c.sampleExt()
	}
	expected := evalClaim
	for i, poly := range p.univariate {
		if expected != extOne.sub(reversed[i]).mul(poly[0]).add(reversed[i].mul(poly[1])) {
			return errBasefoldSumcheck
		}
		expected = poly[0].add(betas[i].mul(poly[1]))
	}

	c.observeExt(p.finalPoly)
	if !c.checkWitness(friProofOfWorkBits, p.powWitness) {
		return errors.New("invalid proof of work witness")
	}
	logLen := len(p.friCommitments)
	if logLen+friLogBlowup > len(twoAdicGenerators)-1 {
		return errors.New("instance overflows the field two_adicity")
	}
	logHeight := uint(logLen + friLogBlowup)
	indices := make([]uint64, friNumQueries)
	for i := range indices {
		indices[i] = c.sampleBits(logHeight)
	}

	batchEvals := make([]ext, len(indices))
	batchIdx := 0
	for round, opening := range p.componentOpenings {
		columns := len(claims[round])
		v := &opening.values
		if len(v.dims) != 2 || v.dims[0] != uint64(len(indices)) || v.dims[1] != uint64(columns) {
			return errBasefoldShape
		}
		roundCoefficients := coefficients[batchIdx : batchIdx+columns]
		for q, row := range v.rows() {
			for j, value := range row {
				batchEvals[q] = batchEvals[q].add(roundCoefficients[j].mul(extFromFelt(value)))
			}
		}
		batchIdx += columns
	}
	for round, opening := range p.componentOpenings {
		if err := verifyMerkleOpenings(commitments[round], indices, &opening, opening.values.dims[1], uint64(logHeight)); err != nil {
			return fmt.Errorf("query failed to verify: %w", err)
		}
	}

	if err := verifyFriQueries(p.friCommitments, indices, p.finalPoly, batchEvals, p.queryOpenings, betas); err != nil {
		return err
	}
	last := p.univariate[len(p.univariate)-1]
	if p.finalPoly != last[0].add(betas[len(betas)-1].mul(last[1])) {
		return errors.New("sumcheck final polynomial mismatch")
	}
	return nil
}

// verifyFriQueries folds each query's opened pairs round by round down to the final polynomial.
func verifyFriQueries(commitments []digest, indices []uint64, finalPoly ext, folded []ext, openings []merkleOpening, betas []ext) error {
	logMaxHeight := len(commitments) + friLogBlowup
	indices = append([]uint64{}, indices...)
	generator := feltFromU32(twoAdicGenerators[logMaxHeight])
	xs := make([]felt, len(indices))
	for i, index := range indices {
		xs[i] = generator.exp(reverseBits(index, uint(logMaxHeight)))
	}
	if len(commitments) != len(openings) || len(commitments) != len(betas) {
		return errBasefoldShape
	}
	minusOne := feltFromU32(twoAdicGenerators[1])
	for round := range commitments {
		logHeight := logMaxHeight - 1 - round
		v := &openings[round].values
		if len(v.dims) != 2 {
			return errBasefoldShape
		}
		if len(indices) != len(folded) || uint64(len(indices)) != v.dims[0] || len(indices) != len(xs) {
			return errBasefoldShape
		}
		for q, row := range v.rows() {
			if len(row) != 8 {
				return errBasefoldShape
			}
			evals := [2]ext{ext(row[0:4]), ext(row[4:8])}
			index := indices[q]
			if evals[index%2] != folded[q] {
				return errors.New("query value mismatch")
			}
			pair := [2]felt{xs[q], xs[q]}
			pair[(index^1)%2] = pair[(index^1)%2].mul(minusOne)
			step := betas[round].sub(extFromFelt(pair[0])).mul(evals[1].sub(evals[0]))
			folded[q] = evals[0].add(step.mulFelt(pair[1].sub(pair[0]).inverse()))
			indices[q] = index >> 1
			xs[q] = xs[q].square()
		}
		if err := verifyMerkleOpenings(commitments[round], indices, &openings[round], 8, uint64(logHeight)); err != nil {
			return fmt.Errorf("query failed to verify: %w", err)
		}
	}
	for _, f := range folded {
		if f != finalPoly {
			return errors.New("query final polynomial mismatch")
		}
	}
	return nil
}

// reverseBits reverses the low n bits of x.
func reverseBits(x uint64, n uint) uint64 {
	if n == 0 {
		return 0
	}
	return bits.Reverse64(x) >> (64 - n)
}

// verifyMerkleOpenings checks rows of a committed tensor against their Merkle paths, and that the
// commitment binds the tree's root to the tensor's height and width.
func verifyMerkleOpenings(commitment digest, indices []uint64, o *merkleOpening, width, logHeight uint64) error {
	if o.width != width {
		return fmt.Errorf("incorrect width: expected %d, got %d", width, o.width)
	}
	if o.logHeight != logHeight {
		return fmt.Errorf("incorrect log height: expected %d, got %d", logHeight, o.logHeight)
	}
	if len(o.paths.dims) != 2 || len(o.values.dims) != 2 ||
		uint64(len(indices)) != o.paths.dims[0] || uint64(len(indices)) != o.values.dims[0] {
		return errMerkleShape
	}
	values, paths := o.values.rows(), o.paths.rows()
	// Authentication paths are independent: no transcript state is touched.
	// Use at most one extra worker, only for substantial batches. Both halves
	// finish before returning, and the earliest input error wins deterministically.
	check := func(start, end int) error {
		for i := start; i < end; i++ {
			index := indices[i]
			if uint64(len(values[i])) != o.width {
				return errMerkleShape
			}
			root := hashFelts(values[i])
			if uint64(len(paths[i])) != o.logHeight {
				return errMerkleShape
			}
			for _, sibling := range paths[i] {
				if index&1 == 0 {
					root = compress(root, sibling)
				} else {
					root = compress(sibling, root)
				}
				index >>= 1
			}
			if root != o.root {
				return errMerkleRoot
			}
			if index != 0 {
				return errMerkleShape
			}
		}
		return nil
	}
	if len(indices) >= 16 && o.logHeight >= 8 && runtime.GOMAXPROCS(0) > 1 {
		middle := len(indices) / 2
		done := make(chan error, 1)
		go func() { done <- check(middle, len(indices)) }()
		first, second := check(0, middle), <-done
		if first != nil {
			return first
		}
		if second != nil {
			return second
		}
	} else if err := check(0, len(indices)); err != nil {
		return err
	}

	if o.logHeight >= fieldOrder || o.width >= fieldOrder {
		return errMerkleOverflow
	}
	shape := hashFelts([]felt{feltFromU64(o.logHeight), feltFromU64(o.width)})
	if compress(o.root, shape) != commitment {
		return errMerkleCommitted
	}
	return nil
}
