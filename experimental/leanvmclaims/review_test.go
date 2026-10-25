package leanvmclaims

import (
	"encoding/binary"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/classkey"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/settlement"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/wire"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"testing"
)

func TestAuthenticatedClassMutations(t *testing.T) {
	f := loadFixtures(t)
	var vectors struct {
		Pin   string `json:"upstream_commit"`
		Cases []struct {
			Name         string
			Offset       int
			Value        uint64
			Accept       bool
			RootAccept   bool `json:"root_accept"`
			RustPanicked bool `json:"rust_panicked"`
		}
	}
	fixture.JSON(t, "testdata/class-mutations.json", &vectors)
	if vectors.Pin != UpstreamCommit || len(vectors.Cases) != 17 {
		t.Fatal("missing class vectors")
	}
	for _, c := range vectors.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if c.RustPanicked {
				t.Fatal("Rust oracle panicked; no verdict")
			}
			key := append([]byte(nil), f.files["class-key.bin"]...)
			binary.LittleEndian.PutUint64(key[c.Offset:], c.Value)
			if c.Name == "class-swap" {
				a := append([]byte(nil), key[16:152]...)
				copy(key[16:152], key[152:288])
				copy(key[152:288], a)
			}
			v, err := NewClassVerifier(key, classkey.Digest(key))
			if err == nil && (verifyEncoded(v, f.files["first/root.bin"], f.files["first/claims.bin"], f.files["first/seal.bin"]) == nil) != c.RootAccept {
				t.Fatal("root verdict differs after reauthentication")
			}
			if (err == nil) != c.Accept {
				t.Fatalf("Go error=%v Rust accept=%v panic=%v", err, c.Accept, c.RustPanicked)
			}
		})
	}
}
func TestConfigSnapshot(t *testing.T) {
	f := loadFixtures(t)
	c := f.verifier.Config()
	original := c.Leaves[0]
	c.Leaves[0].MaxMembers = 0
	c.Small.Claims = 0
	if f.verifier.Config().Leaves[0] != original || f.verifier.Config().Small.Claims == 0 {
		t.Fatal("mutable configuration escaped")
	}
	var zero *ClassVerifier
	if len(zero.Config().Leaves) != 0 {
		t.Fatal("nil config")
	}
}
func TestRootRateBinding(t *testing.T) {
	f := loadFixtures(t)
	r, err := wire.DecodeRoot(f.files["first/root.bin"])
	if err != nil {
		t.Fatal(err)
	}
	r.Rate = 2
	if _, err = settlement.Position(f.verifier.class, r); err == nil {
		t.Fatal("wrong rate accepted")
	}
}
func TestProductionClass(t *testing.T) {
	f := loadFixtureSet(t, "testdata/production", 5)
	if len(f.files["class-key.bin"]) != 60027800 || string(f.files["class-key.digest"]) != "b20ff9b907b2320fb8139f2753172235ae2e0a66fbad11c4a55500dfb4d33b50" {
		t.Fatal("wrong production class")
	}
	if err := verifyEncoded(f.verifier, f.files["root.bin"], f.files["claims.bin"], f.files["seal.bin"]); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"root.bin", "claims.bin", "seal.bin"} {
		b := append([]byte(nil), f.files[name]...)
		b[len(b)/2] ^= 1
		root, claims, seal := f.files["root.bin"], f.files["claims.bin"], f.files["seal.bin"]
		switch name {
		case "root.bin":
			root = b
		case "claims.bin":
			claims = b
		case "seal.bin":
			seal = b
		}
		if verifyEncoded(f.verifier, root, claims, seal) == nil {
			t.Fatal("changed input accepted", name)
		}
	}
}

func TestRustProductionVerdicts(t *testing.T) {
	f := loadFixtureSet(t, "testdata/production", 5)
	for _, part := range []string{"root.bin", "claims.bin", "seal.bin"} {
		f.files["production/"+part] = f.files[part]
		delete(f.files, part)
	}
	replayVerdicts(t, f, "testdata/production-components.json")
}

func FuzzAuthenticatedDescriptor(f *testing.F) {
	x := loadFixtures(f)
	for _, offset := range []uint16{48, 160, 176, 184, 288, 336, 344, 352, 512, 608, 624} {
		f.Add(offset, uint64(0))
	}
	f.Fuzz(func(t *testing.T, offset uint16, value uint64) {
		key := append([]byte(nil), x.files["class-key.bin"]...)
		// Bound edits to descriptor and circuit header; retain the full encoded body.
		at := 16 + 8*(int(offset)%77)
		binary.LittleEndian.PutUint64(key[at:], value)
		_, _ = NewClassVerifier(key, classkey.Digest(key))
	})
}

// Container invariants must reject before expensive semantic layout construction.
func TestClassContainerGuards(t *testing.T) {
	f := loadFixtures(t)
	// LVMXCK02: 16-byte prefix, 17 words per leaf, six shape words,
	// three small-tier words, seal rate/count, roots, placeholders, tier heights.
	leaf0 := 16
	leaf1 := leaf0 + 17*8
	shape := leaf1 + 17*8
	tierHeights := shape + (6+3+2)*8 + (2+2)*32 + 8
	circuitCount := tierHeights + 2*6*8
	for _, edit := range []struct {
		at    int
		value uint64
	}{{leaf0 + 4*8, 0}, {leaf1 + 4*8, 0}, {shape, 0}, {shape + 6*8, 1}, {shape + 7*8, 9}, {shape + 8*8, 5}, {tierHeights, 17}} {
		key := append([]byte(nil), f.files["class-key.bin"]...)
		binary.LittleEndian.PutUint64(key[edit.at:], edit.value)
		if _, err := classkey.Decode(key, classkey.Digest(key)); err == nil {
			t.Fatalf("invalid container offset %d", edit.at)
		}
	}
	key := append([]byte(nil), f.files["class-key.bin"]...)
	k, err := classkey.Decode(key, classkey.Digest(key))
	if err != nil {
		t.Fatal(err)
	}
	prev := k.Circuits[len(k.Circuits)-2].Columns[101]
	lastStart := prev.Offset + prev.Words*8
	key = append(key, key[lastStart:]...)
	binary.LittleEndian.PutUint64(key[circuitCount:], uint64(len(k.Circuits)+1))
	if _, err = classkey.Decode(key, classkey.Digest(key)); err == nil {
		t.Fatal("extra complete circuit accepted")
	}
}
