package pcs

import (
	"encoding/hex"
	"encoding/json"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
	"os"
	"reflect"
	"slices"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestRustMerkle(t *testing.T) {
	var vectors struct {
		Pin      string `json:"upstream_commit"`
		Session  string
		Openings []struct {
			Depth      int
			Root, Hint string
			Queries    []uint64
			RowWords   int `json:"row_words"`
			LeafWords  int `json:"leaf_words"`
			Accept     bool
			Rows       [][]uint64
		}
		Samples []struct {
			Depth, Count int
			Queries      []uint64
		}
	}
	data, e := os.ReadFile("../../testdata/merkle.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(data, &vectors); e != nil {
		t.Fatal(e)
	}
	if vectors.Pin != "da5c964831c993b011464e4fd4a573b7172d5295" {
		t.Fatal("stale pin")
	}
	for i, c := range vectors.Openings {
		var root [32]byte
		copy(root[:], unhex(t, c.Root))
		got, e := OpenRows(root, c.Depth, c.Queries, c.RowWords, c.LeafWords, unhex(t, c.Hint))
		if (e == nil) != c.Accept {
			t.Fatalf("Rust opening %d verdict differs: %v", i, e)
		}
		if c.Accept && !reflect.DeepEqual(got, c.Rows) {
			t.Fatalf("opening %d rows differ", i)
		}
	}
	var session [32]byte
	copy(session[:], unhex(t, vectors.Session))
	for i, c := range vectors.Samples {
		v, e := transcript.NewVerifier(session, []byte{1, 0, 0, 0, 0, 0, 0, 0}, transcript.Proof{})
		if e != nil {
			t.Fatal(e)
		}
		got, e := SampleQueries(v, c.Depth, c.Count)
		if e != nil {
			t.Fatal(e)
		}
		if !slices.Equal(got, c.Queries) {
			t.Fatalf("Rust query sample %d differs", i)
		}
	}
}
func FuzzMerkleHint(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0}, uint8(0), uint8(1))
	f.Fuzz(func(t *testing.T, hint []byte, depthByte, rowByte uint8) {
		depth := int(depthByte % 8)
		row := int(rowByte%32) + 1
		_, _ = OpenRows([32]byte{}, depth, []uint64{0, (1 << uint(depth)) - 1, 0}, row, 32, hint)
	})
}
