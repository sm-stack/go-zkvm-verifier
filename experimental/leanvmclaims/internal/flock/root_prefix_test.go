package flock_test

import (
	"encoding/hex"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"testing"

	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/classkey"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/flock"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/machine"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/recursion"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/settlement"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/wire"
)

// Inspect the real root's flock prefix and settlement components independently,
// and require full recursion verification as well. Public API tests replay the
// complete root/claims/seal verdict corpus.
func TestRustRootComponents(t *testing.T) {
	base := "../../testdata/roots"
	var verdicts struct {
		Pin   string `json:"upstream_commit"`
		Cases []struct {
			Name     string
			Verdicts []struct {
				Action string
				Cut    int
				Accept bool
			}
		}
	}
	fixture.JSON(t, "../../testdata/root-components.json", &verdicts)
	if verdicts.Pin != classkey.Pin || len(verdicts.Cases) != 3 {
		t.Fatal("stale Rust root verdicts")
	}
	for _, c := range verdicts.Cases {
		if len(c.Verdicts) < 40 {
			t.Fatal("missing Rust rejection cases")
		}
		for _, v := range c.Verdicts {
			if v.Accept != (v.Action == "original") {
				t.Fatal("unexpected Rust root verdict")
			}
		}
	}
	_, files := fixture.Load(t, base, classkey.Pin, 12)
	digest, err := hex.DecodeString("de82c3471f61accaa408d475404d7cd911edf04f23873a5d0f4fb9a2344ae171")
	if err != nil {
		t.Fatal(err)
	}
	cfg := classkey.Config{LogBytecode: 12, LogRAM: 17, LogAdvice: 13, ImageWords: 64, LeafHeights: [11]uint64{15, 4, 4, 6, 7, 5, 4, 4, 4, 3, 3}, LeafRate: 1, Arity0: 2, Arity: 2, TreeRate: 1, Claims: 8, Groups: 4}
	loaded, err := classkey.Load(files["class-key.bin"], [32]byte(digest), cfg)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := machine.Load()
	if err != nil {
		t.Fatal(err)
	}
	hashCircuit := &schema.Circuits[schema.HashCircuit]
	scratch := make([]flock.E, len(hashCircuit.Gates))
	for _, name := range []string{"distinct-1", "distinct-2", "distinct-4"} {
		t.Run(name, func(t *testing.T) {
			check := func(action string, cut int, err error) {
				t.Helper()
				for _, c := range verdicts.Cases {
					if c.Name != name {
						continue
					}
					for _, v := range c.Verdicts {
						if v.Action == action && v.Cut == cut {
							if (err == nil) != v.Accept {
								t.Fatalf("Rust verdict %s/%d differs: %v", action, cut, err)
							}
							return
						}
					}
				}
				t.Fatalf("missing Rust case %s/%d", action, cut)
			}
			root, err := wire.DecodeRoot(files[name+"/root.bin"])
			if err != nil {
				t.Fatal(err)
			}
			if root.Circuit != 1 || len(root.Words) != loaded.StatementWords || uint64(root.Rate) != cfg.TreeRate {
				t.Fatal("unexpected real-root statement")
			}
			v, err := transcript.NewVerifier(loaded.RootSession, root.Instance(), root.Proof)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = v.Read(32); err != nil {
				t.Fatal(err)
			} // Commitment::read binds the witness root.
			replay, err := flock.Verify(v, []flock.Shape{{hashCircuit.KLog, hashCircuit.ConstPos, loaded.Layouts[0].Heights[2]}})
			if err != nil {
				t.Fatal(err)
			}
			if err = replay[0].Matrix.Check(hashCircuit, scratch); err != nil {
				t.Fatal(err)
			}
			if err = recursion.Verify(loaded, root); err != nil {
				t.Fatalf("full recursion: %v", err)
			}
			claims, err := wire.DecodeClaims(files[name+"/claims.bin"])
			if err != nil {
				t.Fatal(err)
			}
			if err = settlement.Claims(loaded, root, claims); err != nil {
				t.Fatal(err)
			}
			if err = settlement.Matrices(loaded, root); err != nil {
				t.Fatal(err)
			}
			seal, err := transcript.Decode(files[name+"/seal.bin"])
			if err != nil {
				t.Fatal(err)
			}
			if err = settlement.Seal(loaded, root, seal); err != nil {
				t.Fatal(err)
			}
			wrongClaims := append(wire.Claims(nil), claims...)
			wrongClaims[0].Label[0] ^= 1
			check("claims-label", 0, settlement.Claims(loaded, root, wrongClaims))
			changed := root
			changed.Words = append([]wire.Element(nil), root.Words...)
			changed.Words[len(changed.Words)-1][0] ^= 1
			check("matrix-value", 0, settlement.Matrices(loaded, changed))
			for _, cut := range []int{0, len(seal.Messages) / 2, len(seal.Messages) - 1} {
				bad := seal
				bad.Messages = bad.Messages[:cut]
				check("seal-cut", cut, settlement.Seal(loaded, root, bad))
			}
			bad := seal
			bad.Messages = append([]byte(nil), seal.Messages...)
			bad.Messages[len(bad.Messages)-1] ^= 1
			check("seal-flip", 0, settlement.Seal(loaded, root, bad))
			bad = seal
			bad.Messages = append(append([]byte(nil), seal.Messages...), 0)
			check("seal-trailing", 0, settlement.Seal(loaded, root, bad))
			other := files["distinct-1/seal.bin"]
			if name == "distinct-1" {
				other = files["distinct-2/seal.bin"]
			}
			bad, err = transcript.Decode(other)
			if err != nil {
				t.Fatal(err)
			}
			check("seal-swap", 0, settlement.Seal(loaded, root, bad))
			// This prefix intentionally leaves the bus/constraint/opening stream unread.
			if err = v.EOF(); err == nil {
				t.Fatal("fixture unexpectedly ends at flock prefix")
			}
		})
	}
}
