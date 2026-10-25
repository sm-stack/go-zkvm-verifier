//go:build arm64 && !purego

package leanvm

import (
	"math/rand/v2"
	"testing"
)

func TestPMULLAgainstSoftware(t *testing.T) {
	if !hasPMULL {
		t.Skip("PMULL unavailable or disabled; generic fixture tests still run")
	}
	r := rand.New(rand.NewPCG(191, 77))
	check := func(a, b ext) {
		c0, c1, c2 := extMulPMULL(a.c0, a.c1, a.c2, b.c0, b.c1, b.c2)
		if got := (ext{c0, c1, c2}); got != a.mulSoftware(b) {
			t.Fatalf("extension product differs: %x %x", a, b)
		}
		if kmulPMULL(a.c0, b.c0) != kmulSoftware(a.c0, b.c0) {
			t.Fatal("base product differs")
		}
	}
	for _, x := range []uint64{0, 1, 1 << 63, ^uint64(0), 0xaaaaaaaaaaaaaaaa} {
		for _, y := range []uint64{0, 1, 1 << 63, ^uint64(0), 0x5555555555555555} {
			check(ext{x, x, x}, ext{y, y, y})
		}
	}
	for range 200000 {
		check(ext{r.Uint64(), r.Uint64(), r.Uint64()}, ext{r.Uint64(), r.Uint64(), r.Uint64()})
	}
}
func FuzzFieldBackend(f *testing.F) {
	f.Add(uint64(0), uint64(1), uint64(2), uint64(3), uint64(4), uint64(5))
	f.Add(^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0))
	f.Fuzz(func(t *testing.T, a0, a1, a2, b0, b1, b2 uint64) {
		a, b := ext{a0, a1, a2}, ext{b0, b1, b2}
		if a.mul(b) != a.mulSoftware(b) || kmul(a0, b0) != kmulSoftware(a0, b0) {
			t.Fatal("backend mismatch")
		}
	})
}
