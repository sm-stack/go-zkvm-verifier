package pcs

import (
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"slices"
	"testing"
)

func fromLimbs(w [3]uint64) E { return E{C0: w[0], C1: w[1], C2: w[2]} }
func fromPoints(points [][3]uint64) []E {
	out := make([]E, len(points))
	for i, p := range points {
		out[i] = fromLimbs(p)
	}
	return out
}
func TestRustStack(t *testing.T) {
	var vectors struct {
		Pin     string `json:"upstream_commit"`
		Session string
		Cases   []struct {
			LogN                  int `json:"log_n"`
			Rate, Lanes           int
			Root, Instance, Proof string
			Points                []struct {
				Offset, Slot uint64
				StrideLog    int `json:"stride_log"`
				Point        [][3]uint64
				Value        [3]uint64
			}
			Rings []struct {
				Offset uint64
				Vars   int
				Claims []struct{ Point, Slices [][3]uint64 }
			}
			Mutations []struct {
				Offset int
				Accept bool
			}
			WrongClaimAccept bool `json:"wrong_claim_accept"`
		}
	}
	fixture.JSON(t, "../../testdata/stack.json", &vectors)
	if vectors.Pin != "3e7da4e783dad4c39115e5a231849e52cae5b22f" {
		t.Fatal("stale pin")
	}
	var session [32]byte
	copy(session[:], fixture.Hex(t, vectors.Session))
	for i, c := range vectors.Cases {
		var root [32]byte
		copy(root[:], fixture.Hex(t, c.Root))
		points := make([]PointClaim, len(c.Points))
		for j, p := range c.Points {
			points[j] = PointClaim{p.Offset, p.Slot, p.StrideLog, fromPoints(p.Point), fromLimbs(p.Value)}
		}
		rings := make([]RingClaim, len(c.Rings))
		for j, r := range c.Rings {
			rings[j] = RingClaim{Offset: r.Offset, Vars: r.Vars}
			for _, claim := range r.Claims {
				rings[j].Claims = append(rings[j].Claims, SliceClaim{fromPoints(claim.Point), fromPoints(claim.Slices)})
			}
		}
		instance := fixture.Hex(t, c.Instance)
		proof, e := transcript.Decode(fixture.Hex(t, c.Proof))
		if e != nil {
			t.Fatal(e)
		}
		verify := func(p transcript.Proof) error {
			v, e := transcript.NewVerifier(session, instance, p)
			if e != nil {
				return e
			}
			if e = VerifyStack(v, root, c.LogN, c.Rate, c.Lanes, points, rings); e != nil {
				return e
			}
			return v.EOF()
		}
		if e = verify(proof); e != nil {
			t.Fatalf("Rust stack %d rejected: %v", i, e)
		}
		for j, m := range c.Mutations {
			p := transcript.Proof{Messages: slices.Clone(proof.Messages), Hints: proof.Hints}
			p.Messages[m.Offset] ^= 1
			if (verify(p) == nil) != m.Accept {
				t.Fatalf("stack mutation %d/%d differs", i, j)
			}
		}
		if len(points) > 0 {
			points[0].Value = points[0].Value.Add(one)
		} else {
			rings[0].Claims[0].Slices[0] = rings[0].Claims[0].Slices[0].Add(one)
		}
		if (verify(proof) == nil) != c.WrongClaimAccept {
			t.Fatalf("wrong claim %d differs", i)
		}
	}
}

func TestStackShapeRejectsBeforeReading(t *testing.T) {
	cases := []struct {
		points []PointClaim
		rings  []RingClaim
	}{
		{},
		{points: []PointClaim{{StrideLog: -1}}},
		{points: []PointClaim{{StrideLog: 64}}},
		{points: []PointClaim{{Offset: ^uint64(0)}}},
		{points: []PointClaim{{Slot: 1}}},
		{rings: []RingClaim{{Vars: -1}}},
		{rings: []RingClaim{{Vars: 64}}},
		{rings: []RingClaim{{Vars: 0, Claims: []SliceClaim{{Slices: make([]E, 63)}}}}},
		{rings: []RingClaim{{Vars: 1, Claims: []SliceClaim{{Slices: make([]E, 64)}}}}},
	}
	for i, c := range cases {
		v, e := transcript.NewVerifier([32]byte{}, []byte{1}, transcript.Proof{})
		if e != nil {
			t.Fatal(e)
		}
		if e = VerifyStack(v, [32]byte{}, 15, 1, 1, c.points, c.rings); e == nil {
			t.Fatalf("invalid shape %d accepted", i)
		}
		if e = v.EOF(); e != nil {
			t.Fatalf("shape %d read transcript before rejection: %v", i, e)
		}
	}
}
