package sp1

import (
	"encoding/hex"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func BenchmarkVerify(b *testing.B) {
	f := loadFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := Verify(f.vkeyHash, f.publicValues, f.proof); err != nil {
			b.Fatal(err)
		}
	}
}

// FuzzDecodeCompressedProof also covers arbitrary lengths and encodings, including empty input.
func FuzzDecodeCompressedProof(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 0, 0, 0})
	// Large valid proofs belong to FuzzVerify; keep decoder seeds small.
	f.Add(make([]byte, 128))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = decodeCompressedProof(data) })
}

func TestStatementsMatchRust(t *testing.T) {
	fx := loadFixture(t)
	data, err := os.ReadFile("testdata/statements.json")
	require.NoError(t, err)
	var cases []struct {
		Key          string `json:"key"`
		PublicValues string `json:"public_values"`
		OK           bool   `json:"ok"`
	}
	require.NoError(t, json.Unmarshal(data, &cases))
	require.NotEmpty(t, cases)
	for i, c := range cases {
		key, err := hex.DecodeString(c.Key)
		require.NoError(t, err)
		require.Len(t, key, 32)
		pv, err := hex.DecodeString(c.PublicValues)
		require.NoError(t, err)
		err = Verify([32]byte(key), pv, fx.proof)
		require.Equal(t, c.OK, err == nil, "statement %d: %v", i, err)
	}
}
