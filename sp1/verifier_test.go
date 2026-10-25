package sp1

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// fixture is a real SP1 compressed proof with its program's vkey hash and public values.
type fixture struct {
	vkeyHash     [32]byte
	publicValues []byte
	proof        []byte
}

func loadFixture(t testing.TB) *fixture {
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join("testdata/fixture", name))
		require.NoError(t, err)
		return data
	}
	// vkey_hash.bin is a bincode [KoalaBear; 8]: eight little-endian words.
	words := read("vkey_hash.bin")
	require.Len(t, words, 32)
	var f fixture
	for i := range 8 {
		binary.BigEndian.PutUint32(f.vkeyHash[4*i:], binary.LittleEndian.Uint32(words[4*i:]))
	}
	f.publicValues = read("public_values.bin")
	r, err := gzip.NewReader(bytes.NewReader(read("proof.bin.gz")))
	require.NoError(t, err)
	f.proof, err = io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	return &f
}

func TestVerifiesFixtureProof(t *testing.T) {
	f := loadFixture(t)
	require.NoError(t, Verify(f.vkeyHash, f.publicValues, f.proof))
}

func TestRejectsWrongStatement(t *testing.T) {
	f := loadFixture(t)

	tampered := bytes.Clone(f.publicValues)
	tampered[0] ^= 1
	require.ErrorContains(t, Verify(f.vkeyHash, tampered, f.proof), "public values do not match")

	wrongVkey := f.vkeyHash
	wrongVkey[31] ^= 1
	require.ErrorContains(t, Verify(wrongVkey, f.publicValues, f.proof), "sp1 vk hash mismatch")

	nonCanonical := f.vkeyHash
	binary.BigEndian.PutUint32(nonCanonical[28:], binary.BigEndian.Uint32(nonCanonical[28:])+fieldOrder)
	require.ErrorContains(t, Verify(nonCanonical, f.publicValues, f.proof), "not a KoalaBear digest")
}

// TestMutationsMatchRust replays mutations of the fixture proof and expects the verdicts SP1's Rust
// verifier gave them (testdata/mutations.json, written by the generator).
func TestMutationsMatchRust(t *testing.T) {
	f := loadFixture(t)
	data, err := os.ReadFile("testdata/mutations.json")
	require.NoError(t, err)
	var mutations []struct {
		At       *int   `json:"at"`
		Remove   int    `json:"remove"`
		Insert   string `json:"insert"`
		Truncate *int   `json:"truncate"`
		OK       bool   `json:"ok"`
	}
	require.NoError(t, json.Unmarshal(data, &mutations))
	require.NotEmpty(t, mutations)
	for i, m := range mutations {
		var proof []byte
		if m.Truncate != nil {
			proof = bytes.Clone(f.proof[:*m.Truncate])
		} else {
			insert, err := hex.DecodeString(m.Insert)
			require.NoError(t, err)
			proof = slices.Concat(f.proof[:*m.At], insert, f.proof[*m.At+m.Remove:])
		}
		err := Verify(f.vkeyHash, f.publicValues, proof)
		require.Equal(t, m.OK, err == nil, "mutation %d: %+v: %v", i, m, err)
	}
}

// FuzzVerify checks that no edit of the fixture proof makes the verifier panic. Edits of a real
// proof reach the verifier's later stages, which random bytes never decode into.
func FuzzVerify(f *testing.F) {
	fx := loadFixture(f)
	f.Add(uint32(0), []byte{})
	f.Add(uint32(4), []byte{0xff, 0xff, 0xff, 0xff})
	f.Add(uint32(len(fx.proof)/2), []byte{0x01})
	f.Fuzz(func(t *testing.T, at uint32, put []byte) {
		proof := bytes.Clone(fx.proof)
		offset := int(uint64(at) % uint64(len(proof)))
		switch at % 4 {
		case 0:
			copy(proof[offset:], put)
		case 1:
			proof = proof[:offset]
		case 2:
			proof = slices.Concat(proof[:offset], put, proof[offset:])
		case 3:
			proof = append(proof, put...)
		}
		_ = Verify(fx.vkeyHash, fx.publicValues, proof)
	})
}
