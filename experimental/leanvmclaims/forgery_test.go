package leanvmclaims

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/recursion"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/settlement"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/wire"
)

// The upstream adversarial fixture proves a different circuit, then wraps its
// claims using a forged Wide polynomial. Its wrap recursion proof is VALID;
// acceptance must still fail when the carried Wide claim is settled by the seal.
func TestUpstreamForgedWrap(t *testing.T) {
	f := loadTierFixtures(t)
	base := "testdata/forgery"
	var m struct {
		Pin      string          `json:"upstream_commit"`
		Verdicts map[string]bool `json:"rust_verdicts"`
		Files    map[string]struct {
			Bytes int
			Hash  string `json:"sha256"`
		}
	}
	b, err := os.ReadFile(filepath.Join(base, "provenance.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Pin != UpstreamCommit || len(m.Files) != 5 || len(m.Verdicts) != 3 || !m.Verdicts["wrap_recursion"] || m.Verdicts["child_recursion"] || m.Verdicts["wrap_sealed"] {
		t.Fatal("invalid forgery provenance")
	}
	files := make(map[string][]byte)
	for name, e := range m.Files {
		file, err := os.Open(filepath.Join(base, name+".gz"))
		if err != nil {
			t.Fatal(err)
		}
		gz, err := gzip.NewReader(file)
		if err != nil {
			file.Close()
			t.Fatal(err)
		}
		raw, err := io.ReadAll(io.LimitReader(gz, int64(e.Bytes)+1))
		gz.Close()
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(raw)
		if len(raw) != e.Bytes || hex.EncodeToString(hash[:]) != e.Hash {
			t.Fatalf("corrupt forgery %s", name)
		}
		files[name] = raw
	}
	if string(files["class-key.digest"]) != hex.EncodeToString(f.pin[:]) {
		t.Fatal("forgery belongs to a different class")
	}
	child, err := wire.DecodeRoot(files["child-root.bin"])
	if err != nil {
		t.Fatal(err)
	}
	if recursion.Verify(f.verifier.class, child) == nil {
		t.Fatal("accepted fake child circuit")
	}
	root, err := wire.DecodeRoot(files["root.bin"])
	if err != nil {
		t.Fatal(err)
	}
	if err = recursion.Verify(f.verifier.class, root); err != nil {
		t.Fatalf("upstream valid wrap recursion refused: %v", err)
	}
	claims, err := wire.DecodeClaims(files["claims.bin"])
	if err != nil {
		t.Fatal(err)
	}
	if err = settlement.Claims(f.verifier.class, root, claims); err != nil {
		t.Fatal(err)
	}
	if err = settlement.Matrices(f.verifier.class, root); err != nil {
		t.Fatal(err)
	}
	seal, err := transcript.Decode(files["seal.bin"])
	if err != nil {
		t.Fatal(err)
	}
	if settlement.Seal(f.verifier.class, root, seal) == nil {
		t.Fatal("accepted forged Wide polynomial")
	}
	if f.verifier.VerifySealed(files["root.bin"], files["claims.bin"], files["seal.bin"]) == nil {
		t.Fatal("public API accepted forged wrap")
	}
}
