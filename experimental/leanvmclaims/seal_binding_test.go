package leanvmclaims

import (
	"bytes"
	"encoding/binary"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/classkey"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/recursion"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/settlement"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/wire"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"testing"
)

func TestRustCompactMutations(t *testing.T) {
	f := loadFixtures(t)
	var v struct {
		Pin   string `json:"upstream_commit"`
		Cases []struct {
			Name      string
			Mutations []struct {
				Name, Part string
				At         int
				Accept     bool
			}
		}
	}
	fixture.JSON(t, "testdata/compact-mutations.json", &v)
	if v.Pin != UpstreamCommit || len(v.Cases) != 4 {
		t.Fatal("stale mutations")
	}
	for _, c := range v.Cases {
		for _, m := range c.Mutations {
			t.Run(c.Name+"/"+m.Name, func(t *testing.T) {
				r, s := bytes.Clone(f.files[c.Name+"/root.bin"]), bytes.Clone(f.files[c.Name+"/seal.bin"])
				if m.Part == "root" {
					r[m.At] ^= 1
				} else {
					s[m.At] ^= 1
				}
				e := verifyEncoded(f.verifier, r, f.files[c.Name+"/claims.bin"], s)
				if (e == nil) != m.Accept {
					t.Fatalf("Rust %v; Go %v", m.Accept, e)
				}
			})
		}
	}
}

// Replay the seal separately so root rejection cannot hide a missing seal check.
func TestSealBindings(t *testing.T) {
	f := loadFixtures(t)
	k := f.verifier.class
	for _, name := range []string{"plain-small", "plain-large", "mixed-zk", "one-zk"} {
		t.Run(name, func(t *testing.T) {
			r, e := wire.DecodeRoot(f.files[name+"/root.bin"])
			if e != nil {
				t.Fatal(e)
			}
			p, e := transcript.Decode(f.files[name+"/seal.bin"])
			if e != nil {
				t.Fatal(e)
			}
			_, values, e := settlement.BeginSeal(k, r, p)
			if e != nil {
				t.Fatal(e)
			}
			own, e := recursion.Verify(k, r, values)
			if e != nil {
				t.Fatal(e)
			}
			verify := func(key *classkey.Validated, root wire.Root, proof transcript.Proof) error {
				v, _, e := settlement.BeginSeal(key, root, proof)
				if e != nil {
					return e
				}
				return settlement.Seal(key, root, v, own)
			}
			if e = verify(k, r, p); e != nil {
				t.Fatal(e)
			}
			changed := r
			changed.Hash[0] ^= 1
			if verify(k, changed, p) == nil {
				t.Fatal("seal not bound to whole root")
			}
			altered := *k
			wrongDigest := k.Key.Digest
			wrongDigest[0] ^= 1
			altered.SealSession = transcript.Session([]byte("leanvm/mixed-tree-seal/v3"), wrongDigest[:])
			if verify(&altered, r, p) == nil {
				t.Fatal("seal session not bound")
			}
			for _, part := range []string{"messages", "hints"} {
				q := p
				if part == "messages" {
					q.Messages = append(bytes.Clone(p.Messages), 0)
				} else {
					q.Hints = append(bytes.Clone(p.Hints), 0)
				}
				if verify(k, r, q) == nil {
					t.Fatal("trailing " + part)
				}
			}
			if verify(k, r, transcript.Proof{}) == nil {
				t.Fatal("empty seal")
			}
			v, _, e := settlement.BeginSeal(k, r, p)
			if e != nil {
				t.Fatal(e)
			}
			if settlement.Seal(k, r, v, own[:101]) != settlement.ErrStatement {
				t.Fatal("missing own column")
			}
			at := 3 + k.DensePointVars + k.Polynomials
			for tier := range k.Layouts {
				changed = r
				changed.Words = append([]wire.Element(nil), r.Words...)
				changed.Words[at+tier] = wire.Element{2}
				if verify(k, changed, p) == nil {
					t.Fatal("nonboolean usage")
				}
				if r.Words[at+tier] == (wire.Element{}) {
					changed.Words[at+tier] = wire.Element{}
					changed.Words[3+k.DensePointVars+2+tier] = wire.Element{1}
					if verify(k, changed, p) == nil {
						t.Fatal("unused tier nonzero")
					}
				}
			}
		})
	}
}
func TestConfigSnapshot(t *testing.T) {
	f := loadFixtures(t)
	c := f.verifier.Config()
	c.Leaves[0].MaxMembers++
	c.Small.Claims = 0
	if f.verifier.Config().Small.Claims == 0 {
		t.Fatal("mutable small-tier alias")
	}
	var zero *ClassVerifier
	if len(zero.Config().Leaves) != 0 {
		t.Fatal("nil config")
	}
	if c.Leaves[0].MaxMembers == f.verifier.Config().Leaves[0].MaxMembers {
		t.Fatal("mutable config alias")
	}
}
func TestRootRateBinding(t *testing.T) {
	f := loadFixtures(t)
	r, e := wire.DecodeRoot(f.files["one-zk/root.bin"])
	if e != nil {
		t.Fatal(e)
	}
	r.Rate ^= 1
	if _, e = settlement.Position(f.verifier.class, r); e == nil {
		t.Fatal("wrong rate")
	}
}

func TestSealPrefixCount(t *testing.T) {
	f := loadFixtures(t)
	r, e := wire.DecodeRoot(f.files["one-zk/root.bin"])
	if e != nil {
		t.Fatal(e)
	}
	p, e := transcript.Decode(f.files["one-zk/seal.bin"])
	if e != nil {
		t.Fatal(e)
	}
	for _, count := range []uint64{0, 101, 103, ^uint64(0)} {
		changed := p
		changed.Messages = bytes.Clone(p.Messages)
		binary.LittleEndian.PutUint64(changed.Messages, count)
		if _, _, e = settlement.BeginSeal(f.verifier.class, r, changed); e == nil {
			t.Fatal("invalid count", count)
		}
	}
}

// Keep the authenticated transcript unchanged to isolate the usage contract from
// rejection caused by altered Fiat-Shamir challenges.
func TestUnusedTierContract(t *testing.T) {
	f := loadFixtures(t)
	k := f.verifier.class
	r, e := wire.DecodeRoot(f.files["plain-small/root.bin"])
	if e != nil {
		t.Fatal(e)
	}
	p, e := transcript.Decode(f.files["plain-small/seal.bin"])
	if e != nil {
		t.Fatal(e)
	}
	_, values, e := settlement.BeginSeal(k, r, p)
	if e != nil {
		t.Fatal(e)
	}
	own, e := recursion.Verify(k, r, values)
	if e != nil {
		t.Fatal(e)
	}
	usage := 3 + k.DensePointVars + k.Polynomials
	found := false
	for tier := range k.Layouts {
		if r.Words[usage+tier] != (wire.Element{}) {
			continue
		}
		found = true
		for _, at := range []int{usage + tier, 3 + k.DensePointVars + 2 + tier} {
			changed := r
			changed.Words = append([]wire.Element(nil), r.Words...)
			changed.Words[at] = wire.Element{2}
			v, _, e := settlement.BeginSeal(k, r, p)
			if e != nil {
				t.Fatal(e)
			}
			if e = settlement.Seal(k, changed, v, own); e != settlement.ErrStatement {
				t.Fatalf("invalid unused tier %d: %v", tier, e)
			}
		}
	}
	if !found {
		t.Fatal("fixture has no unused tier")
	}
}
