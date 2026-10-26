package pcs

import (
	"encoding/binary"
	"errors"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"golang.org/x/crypto/blake2s"
	"reflect"
	"slices"
	"testing"
)

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
	fixture.JSON(t, "../../testdata/merkle.json", &vectors)
	if vectors.Pin != "3e7da4e783dad4c39115e5a231849e52cae5b22f" {
		t.Fatal("stale pin")
	}
	for i, c := range vectors.Openings {
		var root [32]byte
		copy(root[:], fixture.Hex(t, c.Root))
		got, e := OpenRows(root, c.Depth, c.Queries, c.RowWords, c.LeafWords, fixture.Hex(t, c.Hint))
		if (e == nil) != c.Accept {
			t.Fatalf("Rust opening %d verdict differs: %v", i, e)
		}
		if c.Accept && !reflect.DeepEqual(got, c.Rows) {
			t.Fatalf("opening %d rows differ", i)
		}
	}
	var session [32]byte
	copy(session[:], fixture.Hex(t, vectors.Session))
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
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0}, uint8(0), uint8(0))
	f.Fuzz(func(t *testing.T, hint []byte, depthByte, rowByte uint8) {
		depth := int(depthByte % 8)
		row := int(rowByte%32) + 1
		_, _ = OpenRows([32]byte{}, depth, []uint64{0, (1 << uint(depth)) - 1, 0}, row, 32, hint)
		// A depth-zero tree has one leaf, giving every complete row an
		// independently computable authentic root and an acceptance oracle.
		if len(hint) == row*8 {
			root := blake2s.Sum256(hint)
			rows, err := OpenRows(root, 0, []uint64{0}, row, row, hint)
			if err != nil || len(rows) != 1 {
				t.Fatalf("valid leaf rejected: %v", err)
			}
			for i, word := range rows[0] {
				if word != binary.LittleEndian.Uint64(hint[i*8:]) {
					t.Fatal("row differs")
				}
			}
		}
	})
}

func TestReadRowsAuthentication(t *testing.T) {
	row := make([]byte, 8)
	binary.LittleEndian.PutUint64(row, 42)
	root := blake2s.Sum256(row)
	for _, corrupt := range []bool{false, true} {
		hint := binary.LittleEndian.AppendUint32(nil, 8)
		hint = append(hint, row...)
		if corrupt {
			hint[4] ^= 1
		}
		v, err := transcript.NewVerifier([32]byte{}, []byte{1}, transcript.Proof{Hints: hint})
		if err != nil {
			t.Fatal(err)
		}
		rows, err := ReadRows(v, root, 0, []uint64{0}, 1, 1)
		if corrupt {
			if !errors.Is(err, transcript.ErrHint) || rows != nil || !errors.Is(v.EOF(), transcript.ErrHint) {
				t.Fatalf("unauthenticated rows: %v %v", rows, err)
			}
		} else if err != nil || len(rows) != 1 || rows[0][0] != 42 || v.EOF() != nil {
			t.Fatalf("valid rows: %v %v", rows, err)
		}
	}
}
