package sp1

import (
	"errors"
	"fmt"
	"math/bits"
)

// numCommitments is the number of committed rounds in a shard proof: preprocessed and main.
const numCommitments = 2

var (
	errJaggedShape         = errors.New("proof has incorrect shape")
	errJaggedPrefixSums    = errors.New("invalid prefix sums")
	errJaggedAreaBounds    = errors.New("round area out of bounds (must be non-zero and less than 2^30)")
	errJaggedFieldOverflow = errors.New("base field overflow")
	errJaggedEval          = errors.New("jagged evaluation proof verification failed")
)

// verifyJagged checks the jagged PCS opening of the committed traces at point, given the claimed
// evaluations of each round's real columns.
func verifyJagged(commitments []digest, point []ext, claims [][]ext, p *jaggedProof, c *challenger) error {
	counts := p.rowColCounts
	if len(counts) == 0 || len(counts) != numCommitments || len(commitments) != numCommitments ||
		len(claims) != numCommitments || len(p.commitments) != numCommitments ||
		p.maxLogRowCount != maxLogRowCount || p.logM >= 30 || len(point) != maxLogRowCount {
		return errJaggedShape
	}

	const stackingHeight = uint64(1) << logStackingHeight
	const maxRowCount = uint64(1) << maxLogRowCount
	maxAddedColumns := max((stackingHeight-1+maxRowCount-1)/maxRowCount, 1)

	var checkedPrefixSum uint64
	for round, rc := range counts {
		if len(rc) < 2 {
			return errJaggedShape
		}
		if uint64(len(rc)) >= fieldOrder {
			return errJaggedFieldOverflow
		}
		for _, e := range rc {
			if e[0] >= fieldOrder || e[1] >= fieldOrder {
				return errJaggedFieldOverflow
			}
		}
		var realColumns uint64
		for _, e := range rc[:len(rc)-2] {
			var carry uint64
			realColumns, carry = bits.Add64(realColumns, e[1], 0)
			if carry != 0 {
				return errJaggedPrefixSums
			}
		}
		if realColumns != uint64(len(claims[round])) {
			return errJaggedShape
		}
		if rc[len(rc)-2][1]+1 > maxAddedColumns || rc[len(rc)-1][1] != 1 {
			return errJaggedShape
		}
		for _, e := range rc {
			hi, area := bits.Mul64(e[0], e[1])
			var carry uint64
			checkedPrefixSum, carry = bits.Add64(checkedPrefixSum, area, 0)
			if hi != 0 || carry != 0 {
				return errJaggedPrefixSums
			}
		}
	}
	if checkedPrefixSum >= 1<<30 {
		return errJaggedAreaBounds
	}

	// The column heights of all rounds, and their prefix sums.
	var prefixSums []uint64
	var total uint64
	for _, rc := range counts {
		for _, e := range rc {
			for range e[1] {
				prefixSums = append(prefixSums, total)
				total += e[0]
			}
		}
	}
	prefixSums = append(prefixSums, total)
	if p.logM != uint64(log2Ceil(total)) {
		return errJaggedShape
	}
	logM := int(p.logM)

	numColVariables := log2Ceil(uint64(len(prefixSums) - 1))
	zCol := c.samplePoint(numColVariables)
	zRow := point

	columnClaims := make([]ext, 0, len(claims[0])+len(claims[1]))
	for _, round := range claims {
		columnClaims = append(columnClaims, round...)
	}

	// Each round's modified commitment binds its original commitment to the table sizes.
	for round, rc := range counts {
		input := make([]felt, 0, 1+2*len(rc))
		input = append(input, feltFromU64(uint64(len(rc))))
		for _, e := range rc {
			input = append(input, feltFromU64(e[0]))
		}
		for _, e := range rc {
			input = append(input, feltFromU64(e[1]))
		}
		if compress(p.commitments[round], hashFelts(input)) != commitments[round] {
			return errors.New("incorrect table sizes")
		}
	}

	roundAreas := make([]uint64, len(counts))
	for round, rc := range counts {
		var area uint64
		for _, e := range rc[:len(rc)-2] {
			area = saturatingAdd(area, saturatingMul(e[0], e[1]))
		}
		if area == 0 || area >= 1<<30 {
			return errJaggedAreaBounds
		}
		roundAreas[round] = area
	}

	addedValues := make([]uint64, len(counts))
	addedColumns := make([]uint64, len(counts))
	for round, area := range roundAreas {
		next := (area + stackingHeight - 1) / stackingHeight * stackingHeight
		addedValues[round] = next - area
		addedColumns[round] = max((addedValues[round]+maxRowCount-1)/maxRowCount, 1)
	}
	for round, rc := range counts {
		n := len(rc)
		if rc[n-2][1]+1 != addedColumns[round] || rc[n-1][1] != 1 || rc[n-2][0] != maxRowCount ||
			rc[n-1][0] != addedValues[round]-(addedColumns[round]-1)*maxRowCount {
			return errJaggedShape
		}
	}
	for _, rc := range counts {
		for _, e := range rc {
			if e[0] > maxRowCount {
				return errJaggedShape
			}
		}
	}

	pointPrefixSums := make([][]ext, len(prefixSums))
	for i, s := range prefixSums {
		pointPrefixSums[i] = pointFromUint(s, logM+1)
	}

	// Insert the padding columns' zero claims after each round's real columns, last round first.
	insertionPoints := make([]int, len(counts))
	position := 0
	for round := range counts {
		position += len(claims[round])
		insertionPoints[round] = position
	}
	for round := len(counts) - 1; round >= 0; round-- {
		at := insertionPoints[round]
		zeros := make([]ext, counts[round][len(counts[round])-2][1]+1)
		columnClaims = append(columnClaims[:at], append(zeros, columnClaims[at:]...)...)
	}
	if len(pointPrefixSums) != len(columnClaims)+1 {
		return errJaggedShape
	}
	for len(columnClaims) != 1<<log2Ceil(uint64(len(columnClaims))) {
		columnClaims = append(columnClaims, extZero)
	}
	if 1<<len(zCol) != len(columnClaims) {
		return errJaggedShape
	}
	if mleEval(columnClaims, zCol) != p.sumcheck.claimedSum {
		return errors.New("sumcheck claim mismatch")
	}
	if err := verifySumcheck(&p.sumcheck, c, log2Ceil(total), 2); err != nil {
		return fmt.Errorf("sumcheck proof verification failed: %w", err)
	}

	for i := 0; i+1 < len(pointPrefixSums); i++ {
		cur, next := pointPrefixSums[i], pointPrefixSums[i+1]
		if len(cur) != len(next) || len(cur) >= 31 || len(cur) == 0 {
			return errJaggedShape
		}
		if fullGeq(cur, next) != extOne {
			return errors.New("monotonicity check failed")
		}
	}

	jaggedEval, err := verifyJaggedEvaluation(pointPrefixSums, zRow, zCol, p.sumcheck.point, &p.jaggedEval, c)
	if err != nil {
		return errJaggedEval
	}
	if p.expectedEval.mul(jaggedEval) != p.sumcheck.eval {
		return errJaggedEval
	}

	totalAreas := make([]uint64, len(roundAreas))
	for i := range roundAreas {
		totalAreas[i] = roundAreas[i] + addedValues[i]
	}
	c.observeExt(p.expectedEval)
	if err := verifyStacked(p.commitments, totalAreas, p.sumcheck.point, &p.stacked, p.expectedEval, c); err != nil {
		return fmt.Errorf("dense pcs verification failed: %w", err)
	}
	return nil
}

func saturatingAdd(a, b uint64) uint64 {
	s, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return ^uint64(0)
	}
	return s
}

func saturatingMul(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	if hi != 0 {
		return ^uint64(0)
	}
	return lo
}

// verifyJaggedEvaluation checks the sumcheck proving the jagged little polynomial's evaluation at
// (zRow, zCol, zTrace), and returns that evaluation.
func verifyJaggedEvaluation(prefixSums [][]ext, zRow, zCol, zTrace []ext, p *sumcheckProof, c *challenger) (ext, error) {
	zColEq := partialLagrange(zCol)
	jaggedEval := p.claimedSum
	c.observeExt(jaggedEval)
	if len(prefixSums) == 0 {
		return extZero, errJaggedShape
	}
	if err := verifySumcheck(p, c, 2*len(prefixSums[0]), 2); err != nil {
		return extZero, err
	}
	half := len(p.point) / 2
	first, second := p.point[:half], p.point[half:]
	if len(first) != len(second) {
		return extZero, errJaggedShape
	}
	if len(prefixSums)-1 > len(zColEq) {
		return extZero, errJaggedShape
	}
	expected := extZero
	for i := 0; i+1 < len(prefixSums) && i < len(zColEq); i++ {
		cur, next := prefixSums[i], prefixSums[i+1]
		if len(cur) != len(next) || len(cur)+len(next) != len(p.point) {
			return extZero, errJaggedShape
		}
		expected = expected.add(zColEq[i].mul(fullLagrangeEval(cur, first).mul(fullLagrangeEval(next, second))))
	}
	expected = expected.mul(branchingProgramEval(zRow, zTrace, first, second))
	if expected != p.eval {
		return extZero, errors.New("jagged evaluation does not match")
	}
	return jaggedEval, nil
}

// branchingProgramEval evaluates the multilinear extension of the jagged indicator: whether
// index = prefixSum + row with prefixSum <= index < nextPrefixSum, as a width-4 branching program
// over the bits from least to most significant.
func branchingProgramEval(zRow, zIndex, prefixSum, nextPrefixSum []ext) ext {
	numVars := max(len(zIndex), len(zRow))
	// States are indexed by carry + 2*comparisonSoFar.
	const success, initial = 2, 0
	var results [4]ext
	results[success] = extOne
	lsb := func(point []ext, i int) ext {
		if len(point) <= i {
			return extZero
		}
		return point[len(point)-i-1]
	}
	for layer := numVars; layer >= 0; layer-- {
		eq := partialLagrange([]ext{lsb(zRow, layer), lsb(zIndex, layer), lsb(prefixSum, layer), lsb(nextPrefixSum, layer)})
		var next [4]ext
		for state := range 4 {
			carry, comparison := state&1, state>>1
			var accum [4]ext
			for i, e := range eq {
				rowBit, indexBit, curBit, nextBit := i>>3&1, i>>2&1, i>>1&1, i&1
				newComparison := comparison
				if indexBit != nextBit {
					newComparison = nextBit
				}
				sum := rowBit + carry + curBit
				if indexBit != sum&1 {
					continue
				}
				out := sum>>1 + newComparison<<1
				accum[out] = accum[out].add(e)
			}
			acc := extZero
			for out := range accum {
				acc = acc.add(accum[out].mul(results[out]))
			}
			next[state] = acc
		}
		results = next
	}
	return results[initial]
}
