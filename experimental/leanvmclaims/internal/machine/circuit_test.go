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
			a, b, err := s.Circuits[c.Index].BilinearCoefficients(func(i int) field.Element { return row[i] }, func(i int) field.Element { return col[i] }, scratch)
			if err != nil || a.Add(elem(p.Alpha).Mul(b)) != elem(p.Value) {
				t.Fatalf("Rust coefficient evaluation %d/%d: %v", c.Index, i, err)
			}
			if got != elem(p.Value) {
				t.Fatalf("Rust matrix %d/%d differs", c.Index, i)
			}
		}
	}
}

func TestBilinearCoefficients(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range s.Circuits {
		// Non-Boolean weights exercise the extension field and every gate in each circuit.
		row := func(i int) field.Element { return field.Element{C0: uint64(i + 1), C1: uint64(i*7 + 3), C2: 11} }
		col := func(i int) field.Element { return field.Element{C0: uint64(i*13 + 5), C1: 17, C2: uint64(i + 2)} }
		scratch := make([]field.Element, len(c.Gates))
		a, b, err := c.BilinearCoefficients(row, col, scratch)
		if err != nil {
			t.Fatal(err)
		}
		for _, alpha := range []field.Element{{}, field.One, {C0: 3, C1: 5, C2: 7}} {
			want, err := c.Bilinear(alpha, row, col, scratch)
			if err != nil {
				t.Fatal(err)
			}
			if a.Add(alpha.Mul(b)) != want {
				t.Fatalf("circuit %d alpha %v", c.Index, alpha)
			}
		}
		if _, _, err = c.BilinearCoefficients(row, col, nil); err == nil {
			t.Fatal("short scratch accepted")
		}
	}
}

func FuzzBilinearCoefficients(f *testing.F) {
	s, err := Load()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(0), uint64(0), uint64(1), uint64(0))
	f.Add(uint8(20), ^uint64(0), uint64(3), uint64(7))
	f.Fuzz(func(t *testing.T, index uint8, x, y, z uint64) {
		c := &s.Circuits[int(index)%len(s.Circuits)]
		row := func(i int) field.Element { return field.Element{C0: uint64(i) ^ x, C1: y, C2: z} }
		col := func(i int) field.Element { return field.Element{C0: z, C1: uint64(i) ^ y, C2: x} }
		scratch := make([]field.Element, len(c.Gates))
		alpha := field.Element{C0: x, C1: y, C2: z}
		a, b, err := c.BilinearCoefficients(row, col, scratch)
		if err != nil {
			t.Fatal(err)
		}
		want, err := c.Bilinear(alpha, row, col, scratch)
		if err != nil {
			t.Fatal(err)
		}
		if a.Add(alpha.Mul(b)) != want {
			t.Fatal("coefficient mismatch")
		}
	})
}
