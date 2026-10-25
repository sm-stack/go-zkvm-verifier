package field

import (
	"encoding/json"
	"os"
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
	data, e := os.ReadFile("../../testdata/field.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(data, &v); e != nil {
		t.Fatal(e)
	}
	if v.Pin != "da5c964831c993b011464e4fd4a573b7172d5295" {
		t.Fatal("stale pin")
	}
	elem := func(w [3]uint64) Element { return Element{w[0], w[1], w[2]} }
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
		x := Element{a, b, c}
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
