package sp1

import "errors"

// A point on the Boolean hypercube's extension is a slice of coordinates; the first coordinate is
// the most significant variable.

// partialLagrange returns eq(b, point) for every b in {0,1}^n, with b's bits read from the first
// coordinate (most significant) to the last.
func partialLagrange(point []ext) []ext {
	evals := make([]ext, 1, 1<<len(point))
	evals[0] = extOne
	for _, c := range point {
		next := make([]ext, 0, 2*len(evals))
		for _, v := range evals {
			prod := v.mul(c)
			next = append(next, v.sub(prod), prod)
		}
		evals = next
	}
	return evals
}

// mleEval evaluates the multilinear extension of values at point: the sum of values[i] * eq(i,
// point) over the indices both cover. Missing values count as zero and extra values are ignored,
// like SP1's dot product along the first dimension.
func mleEval(values []ext, point []ext) ext {
	eq := partialLagrange(point)
	sum := extZero
	for i := 0; i < len(values) && i < len(eq); i++ {
		sum = sum.add(values[i].mul(eq[i]))
	}
	return sum
}

// fullLagrangeEval returns eq(a, b) = prod_i (a_i*b_i + (1-a_i)(1-b_i)).
func fullLagrangeEval(a, b []ext) ext {
	if len(a) != len(b) {
		panic("sp1: eq of points with different dimensions")
	}
	result := extOne
	for i := range a {
		prod := a[i].mul(b[i])
		result = result.mul(prod.add(prod).add(extOne).sub(a[i]).sub(b[i]))
	}
	return result
}

// fullGeq evaluates the multilinear extension of [x >= threshold] at point, where threshold is
// given in binary (most significant bit first).
func fullGeq(threshold, point []ext) ext {
	if len(threshold) != len(point) {
		panic("sp1: geq of points with different dimensions")
	}
	acc := extOne
	for i := len(threshold) - 1; i >= 0; i-- {
		x, y := threshold[i], point[i]
		oneMinusX := extOne.sub(x)
		acc = extOne.sub(y).mul(oneMinusX).add(y.mul(x)).mul(acc).add(y.mul(oneMinusX))
	}
	return acc
}

// pointFromUint returns the dimension-bit binary representation of n, most significant bit first.
func pointFromUint(n uint64, dimension int) []ext {
	point := make([]ext, dimension)
	for i := range point {
		point[i] = extFromU64((n >> (dimension - 1 - i)) & 1)
	}
	return point
}

func feltsToExts(xs []felt) []ext {
	out := make([]ext, len(xs))
	for i, x := range xs {
		out[i] = extFromFelt(x)
	}
	return out
}

// evalUnivariate evaluates the polynomial with the given coefficients (lowest degree first) at x.
func evalUnivariate(coefficients []ext, x ext) ext {
	acc := extZero
	for i := len(coefficients) - 1; i >= 0; i-- {
		acc = acc.mul(x).add(coefficients[i])
	}
	return acc
}

// evalOnePlusEvalZero returns p(0) + p(1) for the polynomial with the given coefficients.
func evalOnePlusEvalZero(coefficients []ext) ext {
	if len(coefficients) == 0 {
		return extZero
	}
	sum := coefficients[0]
	for _, c := range coefficients {
		sum = sum.add(c)
	}
	return sum
}

var (
	errSumcheckShape      = errors.New("invalid sumcheck proof shape")
	errSumcheckRound      = errors.New("sumcheck round inconsistency")
	errSumcheckClaimedSum = errors.New("sumcheck inconsistent with the claimed sum")
	errSumcheckEvaluation = errors.New("sumcheck inconsistent with the evaluation claim")
)

// verifySumcheck checks a sumcheck proof up to its final evaluation claim, absorbing the round
// polynomials into the challenger and sampling the round challenges.
func verifySumcheck(p *sumcheckProof, c *challenger, numVariables, degree int) error {
	n := len(p.polys)
	if n != len(p.point) || n != numVariables || numVariables == 0 {
		return errSumcheckShape
	}
	first := p.polys[0]
	if evalOnePlusEvalZero(first) != p.claimedSum {
		return errSumcheckClaimedSum
	}
	if len(first) != degree+1 {
		return errSumcheckShape
	}
	c.observeExts(first)
	previous := first
	// Challenges are prepended: the last round's challenge is the point's first coordinate.
	challenges := make([]ext, 0, n)
	for _, poly := range p.polys[1:] {
		if len(poly) != degree+1 {
			return errSumcheckShape
		}
		alpha := c.sampleExt()
		challenges = append(challenges, alpha)
		if evalUnivariate(previous, alpha) != evalOnePlusEvalZero(poly) {
			return errSumcheckRound
		}
		c.observeExts(poly)
		previous = poly
	}
	alpha := c.sampleExt()
	challenges = append(challenges, alpha)
	for i := range challenges {
		if challenges[len(challenges)-1-i] != p.point[i] {
			return errSumcheckShape
		}
	}
	if evalUnivariate(previous, alpha) != p.eval {
		return errSumcheckEvaluation
	}
	return nil
}
