// Package testutil loads checked-in test vectors. Missing or corrupt inputs fail tests.
package testutil

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type File struct {
	Bytes int
	Hash  string `json:"sha256"`
}
type Manifest struct {
	Pin      string `json:"upstream_commit"`
	Files    map[string]File
	Verdicts map[string]bool `json:"rust_verdicts"`
}

func JSON(t testing.TB, path string, into any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	JSONBytes(t, b, into)
}
func JSONBytes(t testing.TB, b []byte, into any) {
	t.Helper()
	if err := json.Unmarshal(b, into); err != nil {
		t.Fatal(err)
	}
}
func Hex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func Gzip(t testing.TB, path string, size int) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	b, err := io.ReadAll(io.LimitReader(z, int64(size)+1))
	if err != nil || len(b) != size {
		t.Fatalf("%s: length %d, expected %d: %v", path, len(b), size, err)
	}
	return b
}
func Load(t testing.TB, base, pin string, count int) (Manifest, map[string][]byte) {
	t.Helper()
	var m Manifest
	JSON(t, filepath.Join(base, "provenance.json"), &m)
	if m.Pin != pin || len(m.Files) != count {
		t.Fatalf("%s: invalid provenance", base)
	}
	files := make(map[string][]byte, len(m.Files))
	for name, entry := range m.Files {
		raw := Gzip(t, filepath.Join(base, name+".gz"), entry.Bytes)
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != entry.Hash {
			t.Fatalf("%s: corrupt fixture", name)
		}
		files[name] = raw
	}
	return m, files
}

// ClaimsPin is the generating revision of the claim-tree regression corpus.
const ClaimsPin = "fc3fc9ec0ec218d6b5196ecae85a975590729ae6"
