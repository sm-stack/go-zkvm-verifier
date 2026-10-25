package leanvm

import "math/bits"

// The base field K = GF(2^64) = F2[x]/(x^64 + x^4 + x^3 + x + 1), a uint64, and the challenge
// field E = K[y]/(y^3 + y + 1), an ext. Addition is XOR in both.

// clmul computes a carry-less 128-bit product using integer multiplication.
// Masking off a's top nibble leaves at most 15 bits in each residue class
// modulo 4. Every convolution column is therefore at most 15: carries stay
// within the four-bit holes and cannot corrupt the retained parity bits.
// The removed four coefficients are restored with XOR shifts below.
func clmul(a, b uint64) (hi, lo uint64) {
	x := a & 0x0fffffffffffffff
	x0 := x & 0x1111111111111111
	y0 := b & 0x1111111111111111
	x1 := x & 0x2222222222222222
	y1 := b & 0x2222222222222222
	x2 := x & 0x4444444444444444
	y2 := b & 0x4444444444444444
	x3 := x & 0x8888888888888888
	y3 := b & 0x8888888888888888
	h00, l00 := bits.Mul64(x0, y0)
	h01, l01 := bits.Mul64(x1, y3)
	h02, l02 := bits.Mul64(x2, y2)
	h03, l03 := bits.Mul64(x3, y1)
	hi ^= (h00 ^ h01 ^ h02 ^ h03) & 0x1111111111111111
	lo ^= (l00 ^ l01 ^ l02 ^ l03) & 0x1111111111111111
	h10, l10 := bits.Mul64(x0, y1)
	h11, l11 := bits.Mul64(x1, y0)
	h12, l12 := bits.Mul64(x2, y3)
	h13, l13 := bits.Mul64(x3, y2)
	hi ^= (h10 ^ h11 ^ h12 ^ h13) & 0x2222222222222222
	lo ^= (l10 ^ l11 ^ l12 ^ l13) & 0x2222222222222222
	h20, l20 := bits.Mul64(x0, y2)
	h21, l21 := bits.Mul64(x1, y1)
	h22, l22 := bits.Mul64(x2, y0)
	h23, l23 := bits.Mul64(x3, y3)
	hi ^= (h20 ^ h21 ^ h22 ^ h23) & 0x4444444444444444
	lo ^= (l20 ^ l21 ^ l22 ^ l23) & 0x4444444444444444
	h30, l30 := bits.Mul64(x0, y3)
	h31, l31 := bits.Mul64(x1, y2)
	h32, l32 := bits.Mul64(x2, y1)
	h33, l33 := bits.Mul64(x3, y0)
	hi ^= (h30 ^ h31 ^ h32 ^ h33) & 0x8888888888888888
	lo ^= (l30 ^ l31 ^ l32 ^ l33) & 0x8888888888888888
	m60 := uint64(0) - ((a >> 60) & 1)
	hi ^= (b >> 4) & m60
	lo ^= (b << 60) & m60
	m61 := uint64(0) - ((a >> 61) & 1)
	hi ^= (b >> 3) & m61
	lo ^= (b << 61) & m61
	m62 := uint64(0) - ((a >> 62) & 1)
	hi ^= (b >> 2) & m62
	lo ^= (b << 62) & m62
	m63 := uint64(0) - ((a >> 63) & 1)
	hi ^= (b >> 1) & m63
	lo ^= (b << 63) & m63
	return
}

// spread is the carry-less square of a, as (high, low): bit i moves to bit 2i.
func spread(a uint64) (hi, lo uint64) {
	s := func(x uint64) uint64 {
		x &= 0xFFFF_FFFF
		x = (x | (x << 16)) & 0x0000_FFFF_0000_FFFF
		x = (x | (x << 8)) & 0x00FF_00FF_00FF_00FF
		x = (x | (x << 4)) & 0x0F0F_0F0F_0F0F_0F0F
		x = (x | (x << 2)) & 0x3333_3333_3333_3333
		return (x | (x << 1)) & 0x5555_5555_5555_5555
	}
	return s(a >> 32), s(a)
}

// reduce reduces a 128-bit carry-less product modulo x^64 + x^4 + x^3 + x + 1.
func reduce(hi, lo uint64) uint64 {
	lo ^= hi ^ (hi << 1) ^ (hi << 3) ^ (hi << 4)
	over := (hi >> 63) ^ (hi >> 61) ^ (hi >> 60)
	return lo ^ over ^ (over << 1) ^ (over << 3) ^ (over << 4)
}

func kmulSoftware(a, b uint64) uint64 {
	return reduce(clmul(a, b))
}

func ksquare(a uint64) uint64 {
	return reduce(spread(a))
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

// mul multiplies in E: six base products by three-term Karatsuba, accumulated unreduced, then
// y^3 = y + 1 folds the degree-4 product back into three limbs.
func (a ext) mulSoftware(b ext) ext {
	h00, l00 := clmul(a.c0, b.c0)
	h11, l11 := clmul(a.c1, b.c1)
	h22, l22 := clmul(a.c2, b.c2)
	h01, l01 := clmul(a.c0^a.c1, b.c0^b.c1)
	h02, l02 := clmul(a.c0^a.c2, b.c0^b.c2)
	h12, l12 := clmul(a.c1^a.c2, b.c1^b.c2)
	// p0 = a0b0, p1 = a0b1 + a1b0, p2 = a0b2 + a1b1 + a2b0, p3 = a1b2 + a2b1, p4 = a2b2.
	p1h, p1l := h01^h00^h11, l01^l00^l11
	p2h, p2l := h02^h00^h22^h11, l02^l00^l22^l11
	p3h, p3l := h12^h11^h22, l12^l11^l22
	return ext{
		c0: reduce(h00^p3h, l00^p3l),
		c1: reduce(p1h^p3h^h22, p1l^p3l^l22),
		c2: reduce(p2h^h22, p2l^l22),
	}
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
