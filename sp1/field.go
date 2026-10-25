package sp1

import "math/big"

// fieldOrder is the KoalaBear prime 2^31 - 2^24 + 1.
const fieldOrder = 0x7f000001

// felt is a KoalaBear element in canonical form, in [0, fieldOrder).
type felt uint32

// feltFromU32 reduces x, matching SP1's deserialization of a field element, which accepts any u32.
func feltFromU32(x uint32) felt {
	return felt(x % fieldOrder)
}

func feltFromU64(x uint64) felt {
	return felt(x % fieldOrder)
}

func (a felt) add(b felt) felt {
	s := uint32(a) + uint32(b)
	if s >= fieldOrder {
		s -= fieldOrder
	}
	return felt(s)
}

func (a felt) sub(b felt) felt {
	if a >= b {
		return a - b
	}
	return felt(uint32(a) + fieldOrder - uint32(b))
}

func (a felt) neg() felt {
	if a == 0 {
		return 0
	}
	return fieldOrder - a
}

func (a felt) mul(b felt) felt {
	return felt(uint64(a) * uint64(b) % fieldOrder)
}

func (a felt) square() felt {
	return a.mul(a)
}

func (a felt) exp(e uint64) felt {
	result := felt(1)
	for base := a; e > 0; e >>= 1 {
		if e&1 == 1 {
			result = result.mul(base)
		}
		base = base.square()
	}
	return result
}

// inverse returns 1/a, or 0 for a = 0.
func (a felt) inverse() felt {
	return a.exp(fieldOrder - 2)
}

// ext is an element of the degree-4 binomial extension F[X]/(X^4 - 3), lowest coefficient first.
type ext [4]felt

// extW is the binomial extension's non-residue: X^4 = extW.
const extW = 3

var (
	extZero = ext{}
	extOne  = ext{1}
)

func extFromFelt(a felt) ext {
	return ext{a}
}

func extFromU64(x uint64) ext {
	return ext{feltFromU64(x)}
}

func (a ext) add(b ext) ext {
	return ext{a[0].add(b[0]), a[1].add(b[1]), a[2].add(b[2]), a[3].add(b[3])}
}

func (a ext) sub(b ext) ext {
	return ext{a[0].sub(b[0]), a[1].sub(b[1]), a[2].sub(b[2]), a[3].sub(b[3])}
}

func (a ext) neg() ext {
	return ext{a[0].neg(), a[1].neg(), a[2].neg(), a[3].neg()}
}

func (a ext) mulFelt(b felt) ext {
	return ext{a[0].mul(b), a[1].mul(b), a[2].mul(b), a[3].mul(b)}
}

func (a ext) mul(b ext) ext {
	// Each product is reduced before summing, so the sums stay far below 2^64.
	m := func(x, y felt) uint64 { return uint64(x) * uint64(y) % fieldOrder }
	c0 := m(a[0], b[0]) + extW*((m(a[1], b[3])+m(a[2], b[2])+m(a[3], b[1]))%fieldOrder)
	c1 := m(a[0], b[1]) + m(a[1], b[0]) + extW*((m(a[2], b[3])+m(a[3], b[2]))%fieldOrder)
	c2 := m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + extW*m(a[3], b[3])
	c3 := m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0])
	return ext{felt(c0 % fieldOrder), felt(c1 % fieldOrder), felt(c2 % fieldOrder), felt(c3 % fieldOrder)}
}

func (a ext) square() ext {
	return a.mul(a)
}

func (a ext) isZero() bool {
	return a == extZero
}

// extInverseExponent is p^4 - 2, so that a^(p^4-2) = 1/a for a nonzero a.
var extInverseExponent = func() *big.Int {
	p := big.NewInt(fieldOrder)
	e := new(big.Int).Exp(p, big.NewInt(4), nil)
	return e.Sub(e, big.NewInt(2))
}()

// inverse returns 1/a, or 0 for a = 0.
func (a ext) inverse() ext {
	result := extOne
	for i := extInverseExponent.BitLen() - 1; i >= 0; i-- {
		result = result.square()
		if extInverseExponent.Bit(i) == 1 {
			result = result.mul(a)
		}
	}
	return result
}

func (a ext) div(b ext) ext {
	return a.mul(b.inverse())
}
