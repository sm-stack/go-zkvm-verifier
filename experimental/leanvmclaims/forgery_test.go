package leanvmclaims

import (
	"encoding/hex"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
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
	m, files := fixture.Load(t, base, UpstreamCommit, 5)
	if len(m.Verdicts) != 3 || !m.Verdicts["wrap_recursion"] || m.Verdicts["child_recursion"] || m.Verdicts["wrap_sealed"] {
		t.Fatal("invalid forgery verdicts")
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
