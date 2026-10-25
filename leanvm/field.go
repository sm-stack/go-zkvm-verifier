package leanvm

import (
	"github.com/sm-stack/go-zkvm-verifier/internal/gf2"
	"math/bits"
)

// The base field K = GF(2^64) = F2[x]/(x^64 + x^4 + x^3 + x + 1), a uint64, and the challenge
// field E = K[y]/(y^3 + y + 1), an ext. Addition is XOR in both.

func kmul(a, b uint64) uint64 { return gf2.Mul64(a, b) }
func ksquare(a uint64) uint64 { return gf2.Square64(a) }
func (a ext) mul(b ext) ext {
	c := gf2.Mul192(gf2.Element{C0: a.c0, C1: a.c1, C2: a.c2}, gf2.Element{C0: b.c0, C1: b.c1, C2: b.c2})
	return ext{c.C0, c.C1, c.C2}
}

// kpow returns a^n in K.
func kpow(a uint64, n uint64) uint64 {
	out := uint64(1)
	for ; n > 0; n >>= 1 {
		if n&1 == 1 {
			out = kmul(out, a)
		}
		a = ksquare(a)
	}
	return out
}

// gpow returns g^n in K, g being x (the integer 2).
func gpow(n uint64) uint64 {
	return kpow(2, n)
}

// ext is an element of E: c0 + c1 y + c2 y^2.
type ext struct {
	c0, c1, c2 uint64
}

var (
	extZero = ext{}
	extOne  = ext{c0: 1}
	extGen  = ext{c0: 2}
)

// lift is the K element a as an element of E.
func lift(a uint64) ext {
	return ext{c0: a}
}

func (a ext) isZero() bool {
	return a == extZero
}

func (a ext) add(b ext) ext {
	return ext{a.c0 ^ b.c0, a.c1 ^ b.c1, a.c2 ^ b.c2}
}

// mulK multiplies a by the K element b.
func (a ext) mulK(b uint64) ext {
	return ext{kmul(a.c0, b), kmul(a.c1, b), kmul(a.c2, b)}
}

// square is a*a: in characteristic 2 the cross terms vanish, so it is c0^2 + c1^2 y^2 + c2^2 y^4,
// and y^4 = y^2 + y.
func (a ext) square() ext {
	s0, s1, s2 := ksquare(a.c0), ksquare(a.c1), ksquare(a.c2)
	return ext{c0: s0, c1: s2, c2: s1 ^ s2}
}

// frobenius returns a^(2^k).
func (a ext) frobenius(k int) ext {
	for range k {
		a = a.square()
	}
	return a
}

// pow returns a^n.
func (a ext) pow(n uint64) ext {
	out := extOne
	for ; n > 0; n >>= 1 {
		if n&1 == 1 {
			out = out.mul(a)
		}
		a = a.square()
	}
	return out
}

// inv returns a^(2^192 - 2), the inverse of a nonzero a (and zero for zero).
func (a ext) inv() ext {
	// a^(2^191 - 1), then one squaring.
	r := a
	for range 190 {
		r = r.square().mul(a)
	}
	return r.square()
}

// powers returns [1, base, base^2, ...], count terms.
func powers(base ext, count int) []ext {
	out := make([]ext, count)
	acc := extOne
	for i := range out {
		out[i] = acc
		acc = acc.mul(base)
	}
	return out
}

func sumExt(values []ext) ext {
	var out ext
	for _, v := range values {
		out = out.add(v)
	}
	return out
}

func dot(left, right []ext) ext {
	if len(left) != len(right) {
		panic("leanvm: dot of different lengths")
	}
	var out ext
	for i := range left {
		out = out.add(left[i].mul(right[i]))
	}
	return out
}

// eqKernel returns the table of eq(point, b) over the cube, the first coordinate the lowest bit.
func eqKernel(point []ext) []ext {
	out := make([]ext, 1, 1<<len(point))
	out[0] = extOne
	for _, r := range point {
		n := len(out)
		out = out[:2*n]
		for i := range n {
			hi := out[i].mul(r)
			out[n+i] = hi
			out[i] = out[i].add(hi)
		}
	}
	return out
}

// eqEval returns prod (1 + x_i + y_i).
func eqEval(left, right []ext) ext {
	if len(left) != len(right) {
		panic("leanvm: eq of points with different dimensions")
	}
	out := extOne
	for i := range left {
		out = out.mul(extOne.add(left[i]).add(right[i]))
	}
	return out
}

// multilinearEval evaluates the multilinear extension of table at point, the first coordinate
// folding adjacent entries.
func multilinearEval(table []ext, point []ext) ext {
	if len(table) != 1<<len(point) {
		panic("leanvm: multilinear table has the wrong size")
	}
	return foldMultilinear(append([]ext(nil), table...), point)
}

// foldMultilinear consumes caller-owned scratch storage.
func foldMultilinear(cur []ext, point []ext) ext {
	for _, r := range point {
		half := len(cur) / 2
		for i := range half {
			a, b := cur[2*i], cur[2*i+1]
			cur[i] = a.add(r.mul(a.add(b)))
		}
		cur = cur[:half]
	}
	return cur[0]
}

// multilinearEvalK is multilinearEval of a table of K elements.
func multilinearEvalK(table []uint64, point []ext) ext {
	if len(table) != 1<<len(point) {
		panic("leanvm: multilinear table has the wrong size")
	}
	if len(point) == 0 {
		return lift(table[0])
	}
	r := point[0]
	cur := make([]ext, len(table)/2)
	for i := range cur {
		a, b := table[2*i], table[2*i+1]
		cur[i] = lift(a).add(r.mulK(a ^ b))
	}
	return foldMultilinear(cur, point[1:])
}

// polyEval evaluates the polynomial with these coefficients, constant first, at x.
func polyEval(coefficients []ext, x ext) ext {
	var out ext
	for i := len(coefficients) - 1; i >= 0; i-- {
		out = out.mul(x).add(coefficients[i])
	}
	return out
}

// powersMLE is the multilinear extension of [first * ratio^z] at an LSB-first point.
func powersMLE(first, ratio ext, point []ext) ext {
	out := first
	rp := ratio
	for _, c := range point {
		out = out.mul(extOne.add(c.mul(extOne.add(rp))))
		rp = rp.square()
	}
	return out
}

// intIndexMLE is the multilinear extension of [base ^ (z << shift)], each integer read as the
// field element with those bits.
func intIndexMLE(base uint64, shift int, point []ext) ext {
	out := lift(base)
	for bit, c := range point {
		out = out.add(c.mulK(uint64(1) << (bit + shift)))
	}
	return out
}

// sparseMLE is the multilinear extension of the column holding words at offset and zero
// elsewhere, cut into aligned power-of-two blocks.
func sparseMLE(offset uint64, words []uint64, point []ext) ext {
	var total ext
	for len(words) > 0 {
		size := uint64(1) << (bitLen(uint64(len(words))) - 1)
		if offset != 0 {
			size = min(size, offset&-offset)
		}
		low := bitLen(size) - 1
		selector := extOne
		for j, z := range point[low:] {
			if offset>>(uint(low)+uint(j))&1 == 1 {
				selector = selector.mul(z)
			} else {
				selector = selector.mul(z.add(extOne))
			}
		}
		total = total.add(selector.mul(multilinearEvalK(words[:size], point[:low])))
		offset += size
		words = words[size:]
	}
	return total
}

// bitLen is Python's int.bit_length for a uint64.
func bitLen(x uint64) int { return bits.Len64(x) }

// log2Ceil returns the least k with 2^k >= x, zero for x <= 1.
func log2Ceil(x uint64) int {
	if x <= 1 {
		return 0
	}
	return bitLen(x - 1)
}
