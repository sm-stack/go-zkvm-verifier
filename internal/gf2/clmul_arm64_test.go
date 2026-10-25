//go:build arm64 && !purego

package gf2

import (
	"math/rand/v2"
	"testing"
)

func TestPMULLAgainstSoftware(t *testing.T) {
	if !hasPMULL {
		t.Skip("PMULL unavailable or disabled; generic fixture tests still run")
	}
	r := rand.New(rand.NewPCG(191, 77))
	check := func(a, b Element) {
		c0, c1, c2 := extMulPMULL(a.C0, a.C1, a.C2, b.C0, b.C1, b.C2)
		if got := (Element{c0, c1, c2}); got != Mul192Software(a, b) {
			t.Fatalf("extension product differs: %x %x", a, b)
		}
		if kmulPMULL(a.C0, b.C0) != Mul64Software(a.C0, b.C0) {
			t.Fatal("base product differs")
		}
	}
	for _, x := range []uint64{0, 1, 1 << 63, ^uint64(0), 0xaaaaaaaaaaaaaaaa} {
		for _, y := range []uint64{0, 1, 1 << 63, ^uint64(0), 0x5555555555555555} {
			check(Element{x, x, x}, Element{y, y, y})
		}
	}
	for range 200000 {
		check(Element{r.Uint64(), r.Uint64(), r.Uint64()}, Element{r.Uint64(), r.Uint64(), r.Uint64()})
	}
}
