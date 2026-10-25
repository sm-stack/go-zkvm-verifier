package leanvm

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// edit is an edit of a file, as the vectors write it: [at, "hex"] XORs the bytes in at at,
// [at, remove, "hex"] replaces remove bytes at at with them, and [length] truncates.
type edit []any

func (e edit) apply(t testing.TB, data []byte) []byte {
	num := func(v any) int {
		f, ok := v.(float64)
		require.True(t, ok, "edit %v", e)
		return int(f)
	}
	bytesOf := func(v any) []byte {
		s, ok := v.(string)
		require.True(t, ok, "edit %v", e)
		b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
		require.NoError(t, err)
		return b
	}
	switch len(e) {
	case 1:
		return data[:num(e[0])]
	case 2:
		at := num(e[0])
		for i, b := range bytesOf(e[1]) {
			data[at+i] ^= b
		}
		return data
	case 3:
		at, remove := num(e[0]), num(e[1])
		return slices.Concat(data[:at], bytesOf(e[2]), data[at+remove:])
	}
	t.Fatalf("malformed edit %v", e)
	return nil
}

func applyEdits(t testing.TB, base []byte, edits []edit) []byte {
	data := bytes.Clone(base)
	for _, e := range edits {
		data = e.apply(t, data)
	}
	return data
}

// vectors are what the Rust verifier makes of the fixtures and edits of them
// (testdata/vectors.json, written by tools/leanvm/examples/go_vectors.rs).
type vectors struct {
	Fixtures []struct {
		Elf   string `json:"elf"`
		Proof string `json:"proof"`
	} `json:"fixtures"`
	Programs []struct {
		Elf    string  `json:"elf"`
		Edits  []edit  `json:"edits"`
		Digest *string `json:"digest"`
	} `json:"programs"`
	Proofs []struct {
		Proof    string  `json:"proof"`
		Edits    []edit  `json:"edits"`
		Elf      *string `json:"elf"`
		ElfEdits []edit  `json:"elfEdits"`
		Output   *string `json:"output"`
		OK       bool    `json:"ok"`
	} `json:"proofs"`
}

func loadVectors(t testing.TB) *vectors {
	data, err := os.ReadFile("testdata/vectors.json")
	require.NoError(t, err)
	var v vectors
	require.NoError(t, json.Unmarshal(data, &v))
	return &v
}

// TestProgramDigestsMatchRust computes the program digest of every ELF the vectors list, or fails
// to load it, as the Rust loader does.
func TestProgramDigestsMatchRust(t *testing.T) {
	v := loadVectors(t)
	require.NotEmpty(t, v.Programs)
	elfs := map[string][]byte{}
	for i, c := range v.Programs {
		if elfs[c.Elf] == nil {
			elfs[c.Elf] = readFixture(t, c.Elf)
		}
		digest, err := ProgramDigest(applyEdits(t, elfs[c.Elf], c.Edits))
		if c.Digest == nil {
			require.Error(t, err, "program %d: %s %v", i, c.Elf, c.Edits)
			continue
		}
		require.NoError(t, err, "program %d: %s %v", i, c.Elf, c.Edits)
		require.Equal(t, hashFromHex(t, *c.Digest), digest, "program %d: %s %v", i, c.Elf, c.Edits)
	}
}

// TestProofsMatchRust verifies every proof edit, against every guest and output edit, the vectors
// list and expects the Rust verifier's verdict.
func TestProofsMatchRust(t *testing.T) {
	v := loadVectors(t)
	require.NotEmpty(t, v.Proofs)
	elfOf := map[string]string{}
	for _, f := range v.Fixtures {
		elfOf[f.Proof] = f.Elf
	}
	accepted := 0
	for i, c := range v.Proofs {
		fx := loadFixture(t, elfOf[c.Proof], c.Proof)
		elf := fx.elf
		if c.Elf != nil {
			elf = applyEdits(t, readFixture(t, *c.Elf), c.ElfEdits)
		}
		output := fx.output
		if c.Output != nil {
			output = hashFromHex(t, *c.Output)
		}
		proof := applyEdits(t, fx.proof, c.Edits)
		digest, err := Verify(elf, output, proof)
		name := fmt.Sprintf("proof %d: %s %v elf %v %v output %v", i, c.Proof, c.Edits, c.Elf, c.ElfEdits, c.Output)
		if !c.OK {
			require.Error(t, err, name)
			continue
		}
		accepted++
		require.NoError(t, err, name)
		want, err := ProgramDigest(elf)
		require.NoError(t, err)
		require.Equal(t, want, digest, name)
	}
	require.Positive(t, accepted)
}

func hashFromHex(t testing.TB, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	require.NoError(t, err)
	require.Len(t, b, 32)
	return [32]byte(b)
}
