package classkey

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
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
	b, e := os.ReadFile("../../testdata/classes.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Pin     string `json:"upstream_commit"`
		Classes []vector
	}
	if e = json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
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
func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func input(t testing.TB, v vector) []byte {
	t.Helper()
	f, e := os.Open(filepath.Join("../../testdata", v.Name+".key.gz"))
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	r, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	b, e := io.ReadAll(io.LimitReader(r, int64(v.Bytes)+1))
	if e != nil || len(b) != v.Bytes {
		t.Fatalf("fixture length: %d %v", len(b), e)
	}
	return b
}
func TestRustClassKeyVectors(t *testing.T) {
	for _, v := range vectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			if !v.LoaderOnly {
				t.Fatal("expected explicitly labelled loader-only fixture")
			}
			b := input(t, v)
			desc := unhex(t, v.Descriptor)
			pin := [32]byte(unhex(t, v.Digest))
			if Digest(b) != pin {
				t.Fatal("Rust/Go digest differs")
			}
			k, e := Decode(b, pin, desc)
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
				if d != [32]byte(unhex(t, m.Digest)) {
					t.Fatal("mutated digest", m.Name)
				}
				_, e := Decode(edited, d, desc)
				if (e == nil) != m.Accept {
					t.Fatalf("Rust/Go wire verdict differs for %s: %v", m.Name, e)
				}
			}
			wrong := pin
			wrong[0] ^= 1
			if _, e = Decode(b, wrong, desc); e != ErrDigest {
				t.Fatal("wrong pin accepted")
			}
			for _, n := range []int{0, 7, 8, 183, len(b) - 1} {
				short := b[:n]
				if _, e = Decode(short, Digest(short), desc); e == nil {
					t.Fatalf("truncation %d accepted", n)
				}
			}
			extra := append(bytes.Clone(b), 0)
			if _, e = Decode(extra, Digest(extra), desc); e == nil {
				t.Fatal("trailing byte accepted")
			}
			pos := k.Circuits[0].Columns[0].Offset
			b[pos] ^= 255
			if w, e := k.Word(0, 0, 0); e != nil || w != 0 {
				t.Fatal("caller mutation changed owned key")
			}
			if _, e := k.Word(0, 0, -1); e == nil {
				t.Fatal("negative row")
			}
		})
	}
}
func FuzzClassKeyWire(f *testing.F) {
	f.Add([]byte("LVMXCK01"))
	f.Add(make([]byte, 216))
	for _, v := range vectors(f) {
		b := input(f, v)
		f.Add(bytes.Clone(b[:min(len(b), 4096)]))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		// Rehash so malformed inputs reach parsing instead of stopping at authentication.
		var desc []byte
		end := 192
		if len(b) >= 184 && binary.LittleEndian.Uint64(b[176:184]) == 1 {
			end = 216
		}
		if len(b) >= end {
			desc = b[8:end]
		}
		_, _ = Decode(b, Digest(b), desc)
	})
}
func BenchmarkLoadClassKey(b *testing.B) {
	for _, v := range vectors(b) {
		b.Run(v.Name, func(b *testing.B) {
			data := input(b, v)
			desc := unhex(b, v.Descriptor)
			pin := Digest(data)
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			b.ResetTimer()
			for range b.N {
				if _, e := Decode(data, pin, desc); e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}
