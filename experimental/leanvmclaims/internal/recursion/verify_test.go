package recursion

import (
	"errors"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"slices"
	"testing"

	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/classkey"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/machine"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/settlement"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/wire"
)

func recursionFixture(t *testing.T) (*classkey.Validated, func(string) (wire.Root, [102]E)) {
	t.Helper()
	_, files := fixture.Load(t, "../../testdata/compact", classkey.Pin, 20)
	key := files["class-key.bin"]
	k, err := classkey.Load(key, classkey.Digest(key))
	if err != nil {
		t.Fatal(err)
	}
	return k, func(name string) (wire.Root, [102]E) {
		r, err := wire.DecodeRoot(files[name+"/root.bin"])
		if err != nil {
			t.Fatal(err)
		}
		p, e := transcript.Decode(files[name+"/seal.bin"])
		if e != nil {
			t.Fatal(e)
		}
		_, values, e := settlement.BeginSeal(k, r, p)
		if e != nil {
			t.Fatal(e)
		}
		return r, values
	}
}

func TestRootEOFBinding(t *testing.T) {
	k, root := recursionFixture(t)
	original, values := root("one-zk")
	if _, err := Verify(k, original, values); err != nil {
		t.Fatal(err)
	}
	for _, hints := range []bool{false, true} {
		r := original
		if hints {
			r.Proof.Hints = append(slices.Clone(r.Proof.Hints), 0, 0, 0, 0)
		} else {
			r.Proof.Messages = append(slices.Clone(r.Proof.Messages), 0)
		}
		if _, err := Verify(k, r, values); !errors.Is(err, transcript.ErrTrailing) {
			t.Fatalf("expected trailing error: %v", err)
		}
	}
}

func TestTierLayoutSelection(t *testing.T) {
	k, root := recursionFixture(t)
	for _, name := range []string{"plain-small", "plain-large", "one-zk"} {
		t.Run(name, func(t *testing.T) {
			r, values := root(name)
			tier := int(r.Circuit >> (k.TierShift + 1))
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
			altered.Layouts[(tier+1)%len(k.Layouts)] = other
			if _, err := Verify(&altered, r, values); err != nil {
				t.Fatal(err)
			}
			altered.Layouts[tier] = other
			if _, err := Verify(&altered, r, values); err == nil {
				t.Fatal("wrong layout accepted")
			}
		})
	}
}

// Isolate dispatch for the dedicated ZK tier even when the shipped root is a wrap.
func TestDedicatedTierDispatch(t *testing.T) {
	k, root := recursionFixture(t)
	r, values := root("plain-small")
	changed := *k
	changed.Places = slices.Clone(k.Places)
	changed.Layouts = slices.Clone(k.Layouts)
	position := slices.Index(k.Codes, r.Circuit)
	original := k.Places[position].Tier
	changed.Places[position].Tier = 2
	changed.Layouts[2] = k.Layouts[original]
	if _, e := Verify(&changed, r, values); e != nil {
		t.Fatal(e)
	}
}

func TestHashMatrixBinding(t *testing.T) {
	k, root := recursionFixture(t)
	schema, err := machine.Load()
	if err != nil {
		t.Fatal(err)
	}
	r, values := root("one-zk")
	if err := verifyWithSchema(k, r, schema, &fixedEvaluations{values: values}); err != nil {
		t.Fatal(err)
	}
	changed := *schema
	changed.Circuits = slices.Clone(schema.Circuits)
	hash := &changed.Circuits[changed.HashCircuit]
	// Preserve dimensions and transcript replay, but change the terminal
	// circuit evaluation. Gate metadata is used by the final matrix check.
	hash.Gates = nil
	if err := verifyWithSchema(k, r, &changed, &fixedEvaluations{values: values}); err == nil {
		t.Fatal("missing HASH constraints accepted")
	}
}
