package field

import (
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"testing"
)

func TestRustField(t *testing.T) {
	var v struct {
		Pin   string `json:"upstream_commit"`
		Cases []struct {
			A, B, Product, Square, Inverse, Frobenius [3]uint64
			BaseProduct                               uint64 `json:"base_product"`
			BaseInverse                               uint64 `json:"base_inverse"`
		}
	}
	fixture.JSON(t, "../../testdata/field.json", &v)
	if v.Pin != "59c25cccfd5742f8216f259f9dd4d80d9a5f66e5" {
		t.Fatal("stale pin")
	}
	elem := func(w [3]uint64) Element { return Element{C0: w[0], C1: w[1], C2: w[2]} }
	for i, c := range v.Cases {
		a, b := elem(c.A), elem(c.B)
		if a.Mul(b) != elem(c.Product) || a.Square() != elem(c.Square) || a.Inv() != elem(c.Inverse) || a.Frobenius64() != elem(c.Frobenius) || Mul64(a.C0, b.C0) != c.BaseProduct || Inv64(a.C0) != c.BaseInverse {
			t.Fatalf("Rust field case %d differs", i)
		}
	}
}
func FuzzField(f *testing.F) {
	f.Add(uint64(0), uint64(0), uint64(0))
	f.Add(^uint64(0), uint64(1), uint64(1)<<63)
	f.Fuzz(func(t *testing.T, a, b, c uint64) {
		x := Element{C0: a, C1: b, C2: c}
		if x.Square() != x.Mul(x) {
			t.Fatal("square differs")
		}
		inv := x.Inv()
		if x.IsZero() {
			if !inv.IsZero() {
				t.Fatal("inverse of zero")
			}
		} else if x.Mul(inv) != One {
			t.Fatal("inverse differs")
		}
		y := x
		for range 64 {
			y = y.Square()
		}
		if y != x.Frobenius64() {
			t.Fatal("Frobenius differs")
		}
	})
}
