package machine

import (
	"encoding/json"
	"os"
	"testing"
)

func TestRustLayouts(t *testing.T) {
	var v struct {
		Pin   string `json:"upstream_commit"`
		Cases []struct {
			Heights    [6]uint64
			Accept     bool
			Mu, Lanes  int
			Placements [][4]uint64
		}
	}
	b, err := os.ReadFile("../../testdata/layouts.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if v.Pin != s.Pin || len(v.Cases) != 50 {
		t.Fatal("stale or incomplete layout vectors")
	}
	for _, c := range v.Cases {
		l, err := NewLayout(c.Heights)
		if (err == nil) != c.Accept {
			t.Fatalf("%v: acceptance differs: %v", c.Heights, err)
		}
		if err != nil {
			continue
		}
		if l.Mu != c.Mu || l.Lanes != c.Lanes || len(l.Placements) != len(c.Placements) {
			t.Fatalf("%v: shape differs", c.Heights)
		}
		for i, p := range l.Placements {
			got := [4]uint64{uint64(p.Kind), p.Offset, uint64(p.Vars), 0}
			if p.Kind == 1 {
				got[2], got[3] = uint64(p.Slot), uint64(p.Stride)
			}
			if got != c.Placements[i] {
				t.Fatalf("%v: placement %d: %v != %v", c.Heights, i, got, c.Placements[i])
			}
		}
	}
}

func TestRustLeafSizes(t *testing.T) {
	var v struct {
		Pin   string `json:"upstream_commit"`
		Cases []struct {
			Dims    [3]uint64
			Heights [11]uint64
			Mu      int
			Accept  bool
		} `json:"leaf_cases"`
	}
	b, err := os.ReadFile("../../testdata/layouts.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if v.Pin != s.Pin || len(v.Cases) != 99 {
		t.Fatal("stale or incomplete leaf sizing vectors")
	}
	for _, c := range v.Cases {
		mu, err := s.LeafSize(c.Dims[0], c.Dims[1], c.Dims[2], c.Heights)
		if (err == nil) != c.Accept || err == nil && mu != c.Mu {
			t.Fatalf("%v/%v: got %d,%v; Rust %d,%v", c.Dims, c.Heights, mu, err, c.Mu, c.Accept)
		}
	}
}
