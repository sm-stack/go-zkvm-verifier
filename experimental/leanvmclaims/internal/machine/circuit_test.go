package machine

import (
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/field"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"testing"
)

func elem(w [3]uint64) field.Element { return field.Element{C0: w[0], C1: w[1], C2: w[2]} }
func eqTable(point [][3]uint64) []field.Element {
	p := make([]field.Element, len(point))
	for i, w := range point {
		p[i] = elem(w)
	}
	return field.EqTable(p)
}
func TestRustMatrices(t *testing.T) {
	s, e := Load()
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Pin      string `json:"upstream_commit"`
		Circuits []struct {
			Index  int
			Probes []struct {
				Row, Column  [][3]uint64
				Alpha, Value [3]uint64
			}
		}
	}
	fixture.JSON(t, "../../testdata/matrices.json", &v)
	if v.Pin != s.Pin || len(v.Circuits) != len(s.Circuits) {
		t.Fatal("stale or incomplete matrix vectors")
	}
	maxGates := 0
	for _, c := range s.Circuits {
		maxGates = max(maxGates, len(c.Gates))
	}
	scratch := make([]field.Element, maxGates)
	for _, c := range v.Circuits {
		for i, p := range c.Probes {
			row, col := eqTable(p.Row), eqTable(p.Column)
			got, e := s.Circuits[c.Index].Bilinear(elem(p.Alpha), func(i int) field.Element { return row[i] }, func(i int) field.Element { return col[i] }, scratch)
			if e != nil {
				t.Fatal(e)
			}
			if got != elem(p.Value) {
				t.Fatalf("Rust matrix %d/%d differs", c.Index, i)
			}
		}
	}
}
