package recursion

import (
	"errors"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"slices"
	"testing"

	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/classkey"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/machine"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/wire"
)

func recursionFixture(t *testing.T) (*classkey.Validated, func(string) wire.Root) {
	t.Helper()
	_, files := fixture.Load(t, "../../testdata/roots", fixture.ClaimsV2Pin, 20)
	key := files["class-key.bin"]
	k, err := classkey.Load(key, classkey.Digest(key))
	if err != nil {
		t.Fatal(err)
	}
	return k, func(name string) wire.Root {
		r, err := wire.DecodeRoot(files[name+"/root.bin"])
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
}

func TestRootEOFBinding(t *testing.T) {
	k, root := recursionFixture(t)
	original := root("first")
	if err := Verify(k, original); err != nil {
		t.Fatal(err)
	}
	for _, hints := range []bool{false, true} {
		r := original
		if hints {
			r.Proof.Hints = append(slices.Clone(r.Proof.Hints), 0, 0, 0, 0)
		} else {
			r.Proof.Messages = append(slices.Clone(r.Proof.Messages), 0)
		}
		if err := Verify(k, r); !errors.Is(err, transcript.ErrTrailing) {
			t.Fatalf("expected trailing error: %v", err)
		}
	}
}

func TestTierLayoutSelection(t *testing.T) {
	k, root := recursionFixture(t)
	for _, name := range []string{"first", "small-node", "wide"} {
		t.Run(name, func(t *testing.T) {
			tier := 0
			if name == "wide" {
				tier = 1
			}
			altered := *k
			altered.Layouts = slices.Clone(k.Layouts)
			var heights [6]uint64
			for i, h := range k.Layouts[tier].Heights {
				heights[i] = uint64(h)
			}
			heights[2]++
			other, err := machine.NewLayout(heights)
			if err != nil {
				t.Fatal(err)
			}
			// Distinct derived layouts isolate dispatch from class-key parsing. The
			// original proof must tolerate changes only to the unused tier.
			altered.Layouts[1-tier] = other
			r := root(name)
			if err := Verify(&altered, r); err != nil {
				t.Fatal(err)
			}
			altered.Layouts[tier] = other
			if err := Verify(&altered, r); err == nil {
				t.Fatal("wrong layout accepted")
			}
		})
	}
}

func TestHashMatrixBinding(t *testing.T) {
	k, root := recursionFixture(t)
	schema, err := machine.Load()
	if err != nil {
		t.Fatal(err)
	}
	r := root("first")
	if err := verifyWithSchema(k, r, schema); err != nil {
		t.Fatal(err)
	}
	changed := *schema
	changed.Circuits = slices.Clone(schema.Circuits)
	hash := &changed.Circuits[changed.HashCircuit]
	// Preserve dimensions and transcript replay, but change the terminal
	// circuit evaluation. Gate metadata is used by the final matrix check.
	hash.Gates = nil
	if err := verifyWithSchema(k, r, &changed); err == nil {
		t.Fatal("missing HASH constraints accepted")
	}
}
