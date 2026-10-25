package machine

import (
	"encoding/json"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/field"
	"os"
	"testing"
)

func elem(w [3]uint64) field.Element { return field.Element{C0: w[0], C1: w[1], C2: w[2]} }
func eqTable(point [][3]uint64) []field.Element {
	out := make([]field.Element, 1, 1<<uint(len(point)))
	out[0] = field.One
	for _, w := range point {
		r := elem(w)
		n := len(out)
		out = out[:2*n]
		for i := 0; i < n; i++ {
			high := out[i].Mul(r)
			out[n+i] = high
			out[i] = out[i].Add(high)
		}
	}
	return out
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
	data, e := os.ReadFile("../../testdata/matrices.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(data, &v); e != nil {
		t.Fatal(e)
	}
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
