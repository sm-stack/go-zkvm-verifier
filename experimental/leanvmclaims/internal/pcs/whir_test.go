package pcs

import (
	"encoding/hex"
	"encoding/json"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/field"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"os"
	"slices"
	"testing"
)

func TestRustWHIR(t *testing.T) {
	var vectors struct {
		Pin     string `json:"upstream_commit"`
		Session string
		Cases   []struct {
			LogN                  int `json:"log_n"`
			Rate, Lanes           int
			Root, Instance, Proof string
			Target                [3]uint64
			Weight                [][3]uint64
			WrongTargetAccept     bool `json:"wrong_target_accept"`
			Mutations             []struct {
				Part   string
				Offset int
				Accept bool
			}
		}
	}
	fixture.JSON(t, "../../testdata/whir.json", &vectors)
	if vectors.Pin != "fc3fc9ec0ec218d6b5196ecae85a975590729ae6" {
		t.Fatal("stale pin")
	}
	var session [32]byte
	copy(session[:], fixture.Hex(t, vectors.Session))
	for i, c := range vectors.Cases {
		var root [32]byte
		copy(root[:], fixture.Hex(t, c.Root))
		instance := fixture.Hex(t, c.Instance)
		proof, e := transcript.Decode(fixture.Hex(t, c.Proof))
		if e != nil {
			t.Fatal(e)
		}
		target := E{C0: c.Target[0], C1: c.Target[1], C2: c.Target[2]}
		weights := make([]E, len(c.Weight))
		for j, w := range c.Weight {
			weights[j] = E{C0: w[0], C1: w[1], C2: w[2]}
		}
		verify := func(p transcript.Proof, value E) error {
			v, e := transcript.NewVerifier(session, instance, p)
			if e != nil {
				return e
			}
			e = verifyWHIR(v, root, c.LogN, c.Rate, c.Lanes, value, func(point []E) E { return mle(weights, point[:1]).Mul(field.EqBits(0, point[1:])) })
			if e != nil {
				return e
			}
			return v.EOF()
		}
		if e = verify(proof, target); e != nil {
			t.Fatalf("Rust positive %d rejected: %v", i, e)
		}
		if (verify(proof, target.Add(one)) == nil) != c.WrongTargetAccept {
			t.Fatalf("wrong target %d differs", i)
		}
		for j, m := range c.Mutations {
			p := transcript.Proof{Messages: slices.Clone(proof.Messages), Hints: slices.Clone(proof.Hints)}
			if m.Part == "messages" {
				p.Messages[m.Offset] ^= 1
			} else {
				p.Hints[m.Offset] ^= 1
			}
			if (verify(p, target) == nil) != m.Accept {
				t.Fatalf("Rust mutation %d/%d differs", i, j)
			}
		}
	}
}

func FuzzWHIRProof(f *testing.F) {
	var vectors struct {
		Session string
		Cases   []struct {
			LogN                  int `json:"log_n"`
			Rate, Lanes           int
			Root, Instance, Proof string
			Target                [3]uint64
			Weight                [][3]uint64
		}
	}
	data, e := os.ReadFile("../../testdata/whir.json")
	if e != nil {
		f.Fatal(e)
	}
	if e = json.Unmarshal(data, &vectors); e != nil {
		f.Fatal(e)
	}
	c := vectors.Cases[0]
	decode := func(s string) []byte {
		b, e := hex.DecodeString(s)
		if e != nil {
			f.Fatal(e)
		}
		return b
	}
	var root, session [32]byte
	copy(root[:], decode(c.Root))
	copy(session[:], decode(vectors.Session))
	instance := decode(c.Instance)
	weights := fromPoints(c.Weight)
	target := fromLimbs(c.Target)
	f.Add(decode(c.Proof))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, e := transcript.Decode(b)
		if e != nil {
			return
		}
		v, e := transcript.NewVerifier(session, instance, p)
		if e != nil {
			t.Fatal(e)
		}
		_ = verifyWHIR(v, root, c.LogN, c.Rate, c.Lanes, target, func(point []E) E { return mle(weights, point[:1]).Mul(field.EqBits(0, point[1:])) })
	})
}
