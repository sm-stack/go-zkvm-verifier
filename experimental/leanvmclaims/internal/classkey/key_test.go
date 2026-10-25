package classkey

import (
	"bytes"
	"encoding/binary"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type vector struct {
	PlaceholderDigest string `json:"placeholder_digest"`
	Name              string
	Descriptor        string
	Digest            string
	Bytes             int
	LoaderOnly        bool `json:"loader_only_zero_columns"`
	SemanticCases     []struct {
		Index  int
		Value  uint64
		Accept bool
		Digest string
	} `json:"semantic_cases"`
	Mutations []struct {
		Name   string
		Offset int
		Value  byte
		Accept bool
		Digest string
	}
}

func vectors(t testing.TB) []vector {
	t.Helper()
	var v struct {
		Pin     string `json:"upstream_commit"`
		Classes []vector
	}
	fixture.JSON(t, "../../testdata/classes.json", &v)
	if v.Pin != Pin || len(v.Classes) != 2 {
		t.Fatal("stale or missing Rust vectors")
	}
	manifest, e := os.ReadFile("../../../../tools/leanvm-mixed/Cargo.toml")
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(manifest), `rev = "`+Pin+`"`) {
		t.Fatal("Rust dependency pin differs")
	}
	lock, e := os.ReadFile("../../../../tools/leanvm-mixed/Cargo.lock")
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(lock), "#"+Pin) {
		t.Fatal("Rust lock pin differs")
	}
	return v.Classes
}
func input(t testing.TB, v vector) []byte {
	t.Helper()
	return fixture.Gzip(t, filepath.Join("../../testdata", v.Name+".key.gz"), v.Bytes)
}
func TestRustClassKeyVectors(t *testing.T) {
	for _, v := range vectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			if !v.LoaderOnly {
				t.Fatal("expected explicitly labelled loader-only fixture")
			}
			b := input(t, v)
			pin := [32]byte(fixture.Hex(t, v.Digest))
			if Digest(b) != pin {
				t.Fatal("Rust/Go digest differs")
			}
			k, e := Decode(b, pin)
			if e != nil {
				t.Fatal(e)
			}
			if len(k.Roots) != len(k.Heights) || len(k.Circuits) < 2 {
				t.Fatal("wrong layout")
			}
			for _, m := range v.Mutations {
				if m.Name == "statement-length" {
					continue
				} // Semantic check lives in TestSemanticClasses.
				edited := bytes.Clone(b)
				edited[m.Offset] = m.Value
				d := Digest(edited)
				if d != [32]byte(fixture.Hex(t, m.Digest)) {
					t.Fatal("mutated digest", m.Name)
				}
				_, e := Decode(edited, d)
				if (e == nil) != m.Accept {
					t.Fatalf("Rust/Go wire verdict differs for %s: %v", m.Name, e)
				}
			}
			wrong := pin
			wrong[0] ^= 1
			if _, e = Decode(b, wrong); e != ErrDigest {
				t.Fatal("wrong pin accepted")
			}
			for _, n := range []int{0, 7, 8, 183, len(b) - 1} {
				short := b[:n]
				if _, e = Decode(short, Digest(short)); e == nil {
					t.Fatalf("truncation %d accepted", n)
				}
			}
			extra := append(bytes.Clone(b), 0)
			if _, e = Decode(extra, Digest(extra)); e == nil {
				t.Fatal("trailing byte accepted")
			}
			for _, q := range [][3]int{{-1, 0, 0}, {len(k.Circuits), 0, 0}, {0, -1, 0}, {0, 102, 0}, {0, 0, k.Circuits[0].Columns[0].Words + 1}} {
				if _, e := k.ColumnBytes(q[0], q[1], q[2]); e == nil {
					t.Fatal("column bounds", q)
				}
			}
			pos := k.Circuits[0].Columns[0].Offset
			b[pos] ^= 255
			if w, e := k.ColumnBytes(0, 0, 1); e != nil || binary.LittleEndian.Uint64(w) != 0 {
				t.Fatal("caller mutation changed owned key")
			}
			if _, e := k.ColumnBytes(0, 0, -1); e == nil {
				t.Fatal("negative row")
			}
		})
	}
}
func FuzzClassKeyWire(f *testing.F) {
	f.Add([]byte("LVMXCK02"))
	f.Add(make([]byte, 216))
	for _, v := range vectors(f) {
		b := input(f, v)
		f.Add(bytes.Clone(b[:min(len(b), 4096)]))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		// Rehash so malformed inputs reach parsing instead of stopping at authentication.
		_, _ = Decode(b, Digest(b))
	})
}
func BenchmarkLoadClassKey(b *testing.B) {
	for _, v := range vectors(b) {
		b.Run(v.Name, func(b *testing.B) {
			data := input(b, v)
			pin := Digest(data)
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			b.ResetTimer()
			for range b.N {
				if _, e := Decode(data, pin); e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}
