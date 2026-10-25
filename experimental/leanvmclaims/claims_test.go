// Statement conversion oracle: tools/leanvm-mixed/src/bin/statements.rs.
package leanvmclaims

import (
	"bytes"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/classkey"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"testing"
)

func TestRustStatementMapping(t *testing.T) {
	var vectors struct {
		Pin   string `json:"upstream_commit"`
		Cases []struct {
			Statements []struct{ Vkey, Member string }
			Accept     bool
			Encoding   string
		}
	}
	fixture.JSON(t, "testdata/statements.json", &vectors)
	if vectors.Pin != UpstreamCommit || len(vectors.Cases) != 7 {
		t.Fatal("stale statement vectors")
	}
	for _, c := range vectors.Cases {
		input := make([]Statement, len(c.Statements))
		for i, s := range c.Statements {
			input[i] = Statement{[32]byte(fixture.Hex(t, s.Vkey)), [32]byte(fixture.Hex(t, s.Member))}
		}
		claims, err := ClaimsFromStatements(input)
		if (err == nil) != c.Accept {
			t.Fatalf("mapping accept=%v, Rust=%v", err, c.Accept)
		}
		if err != nil {
			continue
		}
		encoded, err := EncodeClaims(claims)
		if err != nil || !bytes.Equal(encoded, fixture.Hex(t, c.Encoding)) {
			t.Fatalf("Rust mapping differs: %v", err)
		}
	}
}
func FuzzNewClassVerifier(f *testing.F) {
	f.Add([]byte("LVMXCK02"), []byte{})
	f.Add([]byte{}, make([]byte, 32))
	f.Fuzz(func(t *testing.T, key, digest []byte) {
		var pin [32]byte
		copy(pin[:], digest)
		_, _ = NewClassVerifier(key, pin)
		_, _ = NewClassVerifier(key, classkey.Digest(key))
	})
}
