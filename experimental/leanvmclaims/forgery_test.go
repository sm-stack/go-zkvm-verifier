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
	f := loadFixtures(t)
	base := "testdata/forgery"
	m, files := fixture.Load(t, base, fixture.ClaimsV2Pin, 5)
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
	if verifyEncoded(f.verifier, files["root.bin"], files["claims.bin"], files["seal.bin"]) == nil {
		t.Fatal("public API accepted forged wrap")
	}
}

// The pinned upstream tests also exercise member-list constraints and a fake
// same-height first-level circuit under another class's authenticated kind.
func TestUpstreamMemberAttacks(t *testing.T) {
	_, files := fixture.Load(t, "testdata/member-attacks", fixture.ClaimsV2Pin, 34)
	pin := [32]byte(fixture.Hex(t, string(files["class-key.digest"])))
	verifier, err := NewClassVerifier(files["class-key.bin"], pin)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"member-0", "member-1", "member-2", "member-3", "member-4", "foreign-kind", "valid-class-0", "valid-class-1"} {
		t.Run(name, func(t *testing.T) {
			var want struct{ Accept, Recursion bool }
			fixture.JSONBytes(t, files[name+"/verdict.json"], &want)
			expectedPositive := name == "valid-class-0" || name == "valid-class-1"
			if want.Accept != expectedPositive {
				t.Fatal("unexpected upstream verdict")
			}
			root, err := wire.DecodeRoot(files[name+"/root.bin"])
			if err != nil {
				t.Fatal(err)
			}
			err = recursion.Verify(verifier.class, root)
			if (err == nil) != want.Recursion {
				t.Fatalf("recursion: %v; Rust=%v", err, want.Recursion)
			}
			err = verifyEncoded(verifier, files[name+"/root.bin"], files[name+"/claims.bin"], files[name+"/seal.bin"])
			if (err == nil) != want.Accept {
				t.Fatalf("sealed: %v; Rust=%v", err, want.Accept)
			}
		})
	}
}
