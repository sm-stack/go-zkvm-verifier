// Port of rec/proof.rs and the plain table constraints verifier at the pinned revision.
package recursion

import (
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/classkey"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/flock"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/machine"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/pcs"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/settlement"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/wire"
)

func tables(r *reader, b busResult, layout *machine.Layout, s *machine.Schema) ([]pcs.PointClaim, error) {
	xi := r.DrawElement()
	claim := b.totals[0].Add(xi.Mul(b.totals[1]))
	n := 0
	for _, h := range layout.Heights[:5] {
		n = max(n, h)
	}
	if len(b.point) < n {
		return nil, ErrProof
	}
	chi := make([]E, n)
	weights := [5]E{one, one, one, one, one}
	for m := n - 1; m >= 0; m-- {
		claim, chi[m] = r.round(4, claim, nil)
		if r.Err != nil {
			return nil, r.Err
		}
		for t := range weights {
			if layout.Heights[t] > m {
				weights[t] = weights[t].Mul(one.Add(b.point[m]).Add(chi[m]))
			} else {
				weights[t] = weights[t].Mul(chi[m])
			}
		}
	}
	residual := claim
	power := xi.Square()
	global := 1
	var points []pcs.PointClaim
	for t, table := range s.RecTables {
		cols := r.Elements(table.Columns, false)
		if r.Err != nil {
			return nil, r.Err
		}
		own := b.forms[0][t].value(cols).Add(xi.Mul(b.forms[1][t].value(cols)))
		for _, id := range table.Identities {
			own = own.Add(power.Mul(identity(id, cols)))
			power = power.Mul(xi)
		}
		residual = residual.Add(weights[t].Mul(own))
		for _, value := range cols {
			p := layout.Placements[global]
			global++
			point := pcs.PointClaim{Offset: p.Offset, Point: chi[:layout.Heights[t]], Value: value}
			if p.Kind == 1 {
				point.Slot = uint64(p.Slot)
				point.StrideLog = p.Stride
			}
			points = append(points, point)
		}
	}
	if residual != (E{}) {
		return nil, ErrProof
	}
	return points, r.Err
}

// fixedEvaluations collects the exact columns consumed by the root arithmetic.
// Verification is incomplete until the caller authenticates all returned claims.
type fixedEvaluations struct {
	values [102]E
	claims [102]pcs.PointClaim
	seen   [102]bool
	block  uint64
}

// Verify authenticates the native recursion proof using supplied fixed values.
// The caller must authenticate every returned claim in the seal transcript.
func Verify(k *classkey.Validated, root wire.Root, values [102]E) ([]pcs.PointClaim, error) {
	schema, err := machine.Load()
	if err != nil {
		return nil, err
	}
	columns := fixedEvaluations{values: values}
	if err = verifyWithSchema(k, root, schema, &columns); err != nil {
		return nil, err
	}
	for _, seen := range columns.seen {
		if !seen {
			return nil, ErrProof
		}
	}
	return columns.claims[:], nil
}
func verifyWithSchema(k *classkey.Validated, root wire.Root, schema *machine.Schema, columns *fixedEvaluations) error {
	position, err := settlement.Position(k, root)
	if err != nil {
		return err
	}
	tier := k.Places[position].Tier
	layout := k.Layouts[tier]
	local := (root.Circuit >> 1) & ((uint64(1) << uint(k.TierShift)) - 1)
	columns.block = local << uint(layout.FixedVars)
	v, err := transcript.NewVerifier(k.RootSession, root.Instance(), root.Proof)
	if err != nil {
		return err
	}
	bytes, err := v.Read(32)
	if err != nil {
		return err
	}
	commitment := [32]byte(bytes)
	hash := &schema.Circuits[schema.HashCircuit]
	replay, err := flock.Verify(v, []flock.Shape{{KLog: hash.KLog, Pin: hash.ConstPos, LogInstances: layout.Heights[2]}})
	if err != nil {
		return err
	}
	r := reader{FieldReader: transcript.FieldReader{Verifier: v}}
	balance, err := bus(&r, root, layout, schema, columns)
	if err != nil {
		return err
	}
	points, err := tables(&r, balance, layout, schema)
	if err != nil {
		return err
	}
	window := layout.Placements[0]
	ring := pcs.RingClaim{Offset: window.Offset, Vars: window.Vars, Claims: []pcs.SliceClaim{replay[0].Claim}}
	if err = pcs.VerifyStack(v, commitment, layout.Mu, int(root.Rate), layout.Lanes, points, []pcs.RingClaim{ring}); err != nil {
		return err
	}
	if err = v.EOF(); err != nil {
		return err
	}
	return replay[0].Matrix.Check(hash, make([]E, len(hash.Gates)))
}
