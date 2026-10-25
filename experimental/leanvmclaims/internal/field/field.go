// Binary-field arithmetic adapted from the existing Go port. Parameters match
// primitives/field at da5c964831c993b011464e4fd4a573b7172d5295. See NOTICE.
package field

import "math/bits"

// The base field K = GF(2^64) = F2[x]/(x^64 + x^4 + x^3 + x + 1), a uint64, and the challenge
// field E = K[y]/(y^3 + y + 1), an Element. Addition is XOR in both.

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

// spread is the carry-less Square of a, as (high, low): bit i moves to bit 2i.
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

func Square64(a uint64) uint64 {
	return reduce(spread(a))
}

// Pow64 returns a^n in K.
func Pow64(a uint64, n uint64) uint64 {
	out := uint64(1)
	for ; n > 0; n >>= 1 {
		if n&1 == 1 {
			out = Mul64(out, a)
		}
		a = Square64(a)
	}
	return out
}

// GeneratorPow returns g^n in K, g being x (the integer 2).
func GeneratorPow(n uint64) uint64 {
	return Pow64(2, n)
}

// Element is an element of E: C0 + C1 y + C2 y^2.
type Element struct {
	C0, C1, C2 uint64
}

var (
	Zero      = Element{}
	One       = Element{C0: 1}
	Generator = Element{C0: 2}
)

// Lift is the K element a as an element of E.
func Lift(a uint64) Element {
	return Element{C0: a}
}

func (a Element) IsZero() bool {
	return a == Zero
}

func (a Element) Add(b Element) Element {
	return Element{a.C0 ^ b.C0, a.C1 ^ b.C1, a.C2 ^ b.C2}
}

// MulBase multiplies a by the K element b.
func (a Element) MulBase(b uint64) Element {
	return Element{Mul64(a.C0, b), Mul64(a.C1, b), Mul64(a.C2, b)}
}

// mul multiplies in E: six base products by three-term Karatsuba, accumulated unreduced, then
// y^3 = y + 1 folds the degree-4 product back into three limbs.
func (a Element) Mul(b Element) Element {
	h00, l00 := clmul(a.C0, b.C0)
	h11, l11 := clmul(a.C1, b.C1)
	h22, l22 := clmul(a.C2, b.C2)
	h01, l01 := clmul(a.C0^a.C1, b.C0^b.C1)
	h02, l02 := clmul(a.C0^a.C2, b.C0^b.C2)
	h12, l12 := clmul(a.C1^a.C2, b.C1^b.C2)
	// p0 = a0b0, p1 = a0b1 + a1b0, p2 = a0b2 + a1b1 + a2b0, p3 = a1b2 + a2b1, p4 = a2b2.
	p1h, p1l := h01^h00^h11, l01^l00^l11
	p2h, p2l := h02^h00^h22^h11, l02^l00^l22^l11
	p3h, p3l := h12^h11^h22, l12^l11^l22
	return Element{
		C0: reduce(h00^p3h, l00^p3l),
		C1: reduce(p1h^p3h^h22, p1l^p3l^l22),
		C2: reduce(p2h^h22, p2l^l22),
	}
}

// Square is a*a: in characteristic 2 the cross terms vanish, so it is C0^2 + C1^2 y^2 + C2^2 y^4,
// and y^4 = y^2 + y.
func (a Element) Square() Element {
	s0, s1, s2 := Square64(a.C0), Square64(a.C1), Square64(a.C2)
	return Element{C0: s0, C1: s2, C2: s1 ^ s2}
}

func Mul64(a, b uint64) uint64 { return kmulSoftware(a, b) }

// Frobenius64 raises a to 2^64; K is fixed pointwise.
func (a Element) Frobenius64() Element { return Element{a.C0, a.C2, a.C1 ^ a.C2} }

// Inv follows the pinned Rust norm-to-K construction. Zero maps to zero;
// protocol division sites must separately reject zero denominators.
func (a Element) Inv() Element {
	b := a.Frobenius64()
	m := b.Mul(b.Frobenius64())
	return m.MulBase(Inv64(a.Mul(m).C0))
}
func Inv64(a uint64) uint64 {
	sq := func(v uint64, n int) uint64 {
		for range n {
			v = Square64(v)
		}
		return v
	}
	t2 := Mul64(sq(a, 1), a)
	t3 := Mul64(sq(t2, 1), a)
	t6 := Mul64(sq(t3, 3), t3)
	t12 := Mul64(sq(t6, 6), t6)
	t24 := Mul64(sq(t12, 12), t12)
	t48 := Mul64(sq(t24, 24), t24)
	t60 := Mul64(sq(t48, 12), t12)
	t63 := Mul64(sq(t60, 3), t3)
	return sq(t63, 1)
}
func (a Element) Pow(n uint64) Element {
	out := One
	for ; n != 0; n >>= 1 {
		if n&1 != 0 {
			out = out.Mul(a)
		}
		a = a.Square()
	}
	return out
}
