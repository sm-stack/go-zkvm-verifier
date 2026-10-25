package leanvm

import (
	"github.com/sm-stack/go-zkvm-verifier/internal/gf2"
	"testing"
)

// This target also exercises the standalone verifier's adapter to the shared backend.
func FuzzFieldBackend(f *testing.F) {
	f.Add(uint64(0), uint64(1), uint64(2), uint64(3), uint64(4), uint64(5))
	f.Add(^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0))
	f.Fuzz(func(t *testing.T, a0, a1, a2, b0, b1, b2 uint64) {
		a, b := ext{a0, a1, a2}, ext{b0, b1, b2}
		want := gf2.Mul192Software(gf2.Element{C0: a0, C1: a1, C2: a2}, gf2.Element{C0: b0, C1: b1, C2: b2})
		if a.mul(b) != (ext{want.C0, want.C1, want.C2}) || kmul(a0, b0) != gf2.Mul64Software(a0, b0) {
			t.Fatal("backend mismatch")
		}
	})
}
