package leanvm

import (
	"github.com/sm-stack/go-zkvm-verifier/internal/gf2"
	"github.com/stretchr/testify/require"
	"math/rand/v2"
	"testing"
)

func clmulSlow(a, b uint64) (hi, lo uint64) {
	for i := 0; i < 64; i++ {
		if (a>>i)&1 != 0 {
			lo ^= b << i
			if i > 0 {
				hi ^= b >> (64 - i)
			}
		}
	}
	return
}
func TestCarrylessProducts(t *testing.T) {
	r := rand.New(rand.NewPCG(11, 19))
	check := func(a, b uint64) {
		h, l := clmulSlow(a, b)
		x, y := gf2.Clmul(a, b)
		require.Equal(t, h, x)
		require.Equal(t, l, y)
	}
	for _, a := range []uint64{0, 1, 1 << 63, 0xffffffffffffffff, 0xaaaaaaaaaaaaaaaa, 0x1111111111111111} {
		for _, b := range []uint64{0, 1, 1 << 63, 0xffffffffffffffff, 0x5555555555555555} {
			check(a, b)
		}
	}
	for range 100000 {
		check(r.Uint64(), r.Uint64())
	}
}

var productSink uint64

func BenchmarkCarryless(b *testing.B) {
	for _, tc := range []struct {
		name string
		f    func(uint64, uint64) (uint64, uint64)
	}{{"wide", gf2.Clmul}} {
		b.Run(tc.name, func(b *testing.B) {
			var x uint64 = 7
			for range b.N {
				h, l := tc.f(x, 0xfedcba9876543210)
				x = h ^ l
			}
			productSink = x
		})
	}
}

func TestFactoredBilinear(t *testing.T) {
	r := rand.New(rand.NewPCG(4, 5))
	random := func() ext { return ext{r.Uint64(), r.Uint64(), r.Uint64()} }
	for _, c := range classCircuits() {
		hiR, hiC := make([]ext, (1<<c.logSize)/kBits), make([]ext, (1<<c.logSize)/kBits)
		loR, loC := make([]ext, kBits), make([]ext, kBits)
		for i := range hiR {
			hiR[i], hiC[i] = random(), random()
		}
		for i := range loR {
			loR[i], loC[i] = random(), random()
		}
		row, col := make([]ext, 1<<c.logSize), make([]ext, 1<<c.logSize)
		for i := range row {
			row[i] = hiR[i/kBits].mul(loR[i%kBits])
			col[i] = hiC[i/kBits].mul(loC[i%kBits])
		}
		alpha := random()
		require.Equal(t, c.bilinearExpanded(alpha, row, col), c.bilinear(alpha, hiR, loR, hiC, loC))
	}
}

func TestExtensionProductIndependent(t *testing.T) {
	r := rand.New(rand.NewPCG(25, 35))
	for range 10000 {
		a, b := ext{r.Uint64(), r.Uint64(), r.Uint64()}, ext{r.Uint64(), r.Uint64(), r.Uint64()}
		aa, bb := [3]uint64{a.c0, a.c1, a.c2}, [3]uint64{b.c0, b.c1, b.c2}
		var coefficients [5]uint64
		for i, x := range aa {
			for j, y := range bb {
				h, l := clmulSlow(x, y)
				coefficients[i+j] ^= gf2.Reduce(h, l)
			}
		}
		want := ext{coefficients[0] ^ coefficients[3], coefficients[1] ^ coefficients[3] ^ coefficients[4], coefficients[2] ^ coefficients[4]}
		require.Equal(t, want, a.mul(b))
	}
}
