package leanvmclaims

import (
	"encoding/binary"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/classkey"
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
	fixture.JSON(t, "testdata/compact-class-mutations.json", &vectors)
	if vectors.Pin != UpstreamCommit || len(vectors.Cases) != 18 {
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
				a := append([]byte(nil), key[24:168]...)
				copy(key[24:168], key[168:312])
				copy(key[168:312], a)
			}
			v, err := NewClassVerifier(key, classkey.Digest(key))
			if err == nil && (verifyEncoded(v, f.files["one-zk/root.bin"], f.files["one-zk/claims.bin"], f.files["one-zk/seal.bin"]) == nil) != c.RootAccept {
				t.Fatal("root verdict differs after reauthentication")
			}
			if (err == nil) != c.Accept {
				t.Fatalf("Go error=%v Rust accept=%v panic=%v", err, c.Accept, c.RustPanicked)
			}
		})
	}
}

func TestClassContainerGuards(t *testing.T) {
	f := loadFixtures(t)
	const leaf0 = 24
	const leaf1 = leaf0 + 144
	const shape = leaf0 + 3*144
	const heights = shape + (6+3+2)*8 + 6*32 + 8
	const count = heights + 3*48
	for _, edit := range []struct {
		at    int
		value uint64
	}{{leaf0 + 32, 0}, {leaf1 + 32, 0}, {shape, 0}, {shape + 48, 1}, {shape + 56, 16386}, {shape + 64, 1025}, {heights, 33}, {8, 0}, {16, 0}, {shape + 40, 2}} {
		key := append([]byte(nil), f.files["class-key.bin"]...)
		binary.LittleEndian.PutUint64(key[edit.at:], edit.value)
		if _, e := classkey.Decode(key, classkey.Digest(key)); e == nil {
			t.Fatalf("container offset %d", edit.at)
		}
	}
	key := append([]byte(nil), f.files["class-key.bin"]...)
	k, e := classkey.Decode(key, classkey.Digest(key))
	if e != nil {
		t.Fatal(e)
	}
	key = append(key, key[len(key)-56:]...)
	binary.LittleEndian.PutUint64(key[count:], uint64(len(k.Circuits)+1))
	if _, e := classkey.Decode(key, classkey.Digest(key)); e == nil {
		t.Fatal("extra circuit")
	}
	key = append([]byte(nil), f.files["class-key.bin"]...)
	key[count+16] ^= 1
	if _, e := classkey.Decode(key, classkey.Digest(key)); e == nil {
		t.Fatal("circuit heights")
	}
}
func FuzzAuthenticatedDescriptor(f *testing.F) {
	x := loadFixtures(f)
	f.Add(uint16(56), uint64(0))
	f.Fuzz(func(t *testing.T, at uint16, v uint64) {
		key := append([]byte(nil), x.files["class-key.bin"]...)
		offset := 8 * (int(at) % (len(key) / 8))
		binary.LittleEndian.PutUint64(key[offset:], v)
		_, _ = NewClassVerifier(key, classkey.Digest(key))
	})
}
