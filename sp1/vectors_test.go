package sp1

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// vectors are values computed by SP1's Rust code (testdata/vectors.json, written by the generator
// in tools/sp1/examples/go_verifier_tables.rs).
type vectors struct {
	Permutation []struct {
		In  []uint32 `json:"in"`
		Out []uint32 `json:"out"`
	} `json:"permutation"`
	Hash []struct {
		In  []uint32 `json:"in"`
		Out []uint32 `json:"out"`
	} `json:"hash"`
	Compress struct {
		Left  []uint32 `json:"left"`
		Right []uint32 `json:"right"`
		Out   []uint32 `json:"out"`
	} `json:"compress"`
	Ext []struct {
		A   []uint32 `json:"a"`
		B   []uint32 `json:"b"`
		Mul []uint32 `json:"mul"`
		Div []uint32 `json:"div"`
	} `json:"ext"`
	Challenger [][]uint32 `json:"challenger"`
	Chips      []struct {
		Chip         string       `json:"chip"`
		Alpha        []uint32     `json:"alpha"`
		PublicValues []uint32     `json:"publicValues"`
		Preprocessed [][]uint32   `json:"preprocessed"`
		Main         [][]uint32   `json:"main"`
		Value        []uint32     `json:"value"`
		ZeroValue    []uint32     `json:"zeroValue"`
		Betas        [][]uint32   `json:"betas"`
		Interactions [][][]uint32 `json:"interactions"`
	} `json:"chips"`
}

func loadVectors(t *testing.T) *vectors {
	data, err := os.ReadFile("testdata/vectors.json")
	require.NoError(t, err)
	var v vectors
	require.NoError(t, json.Unmarshal(data, &v))
	return &v
}

func felts(xs []uint32) []felt {
	out := make([]felt, len(xs))
	for i, x := range xs {
		out[i] = feltFromU32(x)
	}
	return out
}

func extOf(xs []uint32) ext {
	return ext(felts(xs))
}

func extsOf(xss [][]uint32) []ext {
	out := make([]ext, len(xss))
	for i, xs := range xss {
		out[i] = extOf(xs)
	}
	return out
}

func TestPermutationMatchesRust(t *testing.T) {
	for _, c := range loadVectors(t).Permutation {
		var state [poseidon2Width]felt
		copy(state[:], felts(c.In))
		permute(&state)
		require.Equal(t, felts(c.Out), state[:])
	}
}

func TestHashAndCompressMatchRust(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.Hash {
		out := hashFelts(felts(c.In))
		require.Equal(t, felts(c.Out), out[:], "input length %d", len(c.In))
	}
	out := compress(digest(felts(v.Compress.Left)), digest(felts(v.Compress.Right)))
	require.Equal(t, felts(v.Compress.Out), out[:])
}

func TestExtensionArithmeticMatchesRust(t *testing.T) {
	for _, c := range loadVectors(t).Ext {
		a, b := extOf(c.A), extOf(c.B)
		require.Equal(t, extOf(c.Mul), a.mul(b))
		require.Equal(t, extOf(c.Div), a.div(b))
		require.Equal(t, extOne, b.mul(b.inverse()))
	}
}

func TestChallengerMatchesRust(t *testing.T) {
	want := loadVectors(t).Challenger
	c := newChallenger()
	for i := range 5 {
		c.observe(felt(i))
	}
	require.Equal(t, extOf(want[0]), c.sampleExt())
	var sevens digest
	for i := range sevens {
		sevens[i] = 7
	}
	c.observeDigest(sevens)
	require.Equal(t, extOf(want[1]), c.sampleExt())
	require.Equal(t, extOf(want[2]), c.sampleExt())
	require.Equal(t, uint64(want[3][0]), c.sampleBits(22))
	for i := range 13 {
		c.observe(felt(100 + i))
	}
	require.Equal(t, uint64(want[4][0]), c.sampleBits(10))
	require.True(t, c.checkWitness(8, felt(want[5][0])))
	require.Equal(t, extOf(want[6]), c.sampleExt())
}

func TestChipsMatchRust(t *testing.T) {
	cases := loadVectors(t).Chips
	require.Len(t, cases, len(compressChips))
	for i, c := range cases {
		chip := &compressChips[i]
		require.Equal(t, c.Chip, chip.name)
		alpha, pvs := extOf(c.Alpha), felts(c.PublicValues)
		prep, main := extsOf(c.Preprocessed), extsOf(c.Main)
		require.Equal(t, extOf(c.Value), chip.evalConstraints(prep, main, alpha, pvs), chip.name)
		zeroPrep, zeroMain := make([]ext, len(prep)), make([]ext, len(main))
		require.Equal(t, extOf(c.ZeroValue), chip.evalConstraints(zeroPrep, zeroMain, alpha, pvs), chip.name)

		betas := extsOf(c.Betas)
		interactions := append(append([]interaction{}, chip.sends...), chip.receives...)
		require.Len(t, c.Interactions, len(interactions))
		for j, in := range interactions {
			numerator, denominator := in.eval(prep, main, alpha, betas)
			require.Equal(t, extsOf(c.Interactions[j]), []ext{numerator, denominator}, "%s interaction %d", chip.name, j)
		}
	}
}
