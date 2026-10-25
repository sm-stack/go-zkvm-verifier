// CREDIT: https://github.com/succinctlabs/flock, MIT OR Apache-2.0.
// Port of flock reduction, zerocheck and lincheck at 59c25cccfd5742f8216f259f9dd4d80d9a5f66e5.
package flock

import (
	"errors"
	"fmt"
	"slices"

	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/field"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/machine"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/pcs"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
)

type E = field.Element

var one = field.One
var ErrReduction = errors.New("leanvmclaims: flock reduction mismatch")

var ErrZerocheckTerminal = fmt.Errorf("%w: zerocheck terminal", ErrReduction)

type Shape struct{ KLog, Pin, LogInstances int }
type MatrixClaim struct {
	Alpha, Skip, Value E
	Rows, Cols, Slices []E
}
type Replay struct {
	Claim  pcs.SliceClaim
	Matrix MatrixClaim
}

type reader struct{ transcript.FieldReader }

func (r *reader) round(claim E, eq *E) (E, E) {
	a, b := r.ReadElement(), r.ReadElement()
	c := a
	if eq == nil {
		a = claim.Add(b)
	} else {
		c = claim.Add(eq.Mul(a.Add(b)))
	}
	x := r.DrawElement()
	return c.Add(x.Mul(a.Add(x.Mul(b)))), x
}

// Verify reduces R1CS validity to witness openings and matrix claims. Both must
// be checked by the caller; this function alone does not accept a proof.
func Verify(v *transcript.Verifier, shapes []Shape) ([]Replay, error) {
	if len(shapes) == 0 {
		return nil, ErrReduction
	}
	maxM, maxRest := 0, 0
	for _, s := range shapes {
		// Bounds follow the pinned recursion commitment profile, not proof bytes.
		if s.KLog < 6 || s.KLog > machineMaxK || s.LogInstances < 0 || s.LogInstances > 32 || s.KLog+s.LogInstances < 13 || s.Pin < 0 || s.Pin >= 1<<uint(s.KLog) {
			return nil, ErrReduction
		}
		maxM = max(maxM, s.KLog+s.LogInstances)
		maxRest = max(maxRest, s.KLog-6)
	}
	r := reader{FieldReader: transcript.FieldReader{Verifier: v}}
	outer := r.Elements(maxM-13, true)
	lambda := r.DrawElement()
	round1 := r.Elements(skipSize, false)
	z := r.DrawElement()
	if r.Err != nil {
		return nil, r.Err
	}
	vanish := vanishing(z, skipSize)
	claim := firstRound(z, vanish, round1)
	coordinates := append(slices.Clone(fixedChallenges[:]), outer...)
	mlv := make([]E, len(coordinates))
	for i, eq := range coordinates {
		claim, mlv[i] = r.round(claim, &eq)
		if r.Err != nil {
			return nil, r.Err
		}
	}
	evals := make([][3]E, len(shapes))
	terminal, weight := E{}, one
	for i := range evals {
		a, b, c := r.ReadElement(), r.ReadElement(), r.ReadElement()
		evals[i] = [3]E{a, b, c}
		terminal = terminal.Add(weight.Mul(a.Mul(b).Add(c)))
		weight = weight.Mul(lambda)
	}
	if r.Err != nil {
		return nil, r.Err
	}
	if terminal != claim {
		return nil, ErrZerocheckTerminal
	}
	alpha := r.DrawElement()
	alpha2 := alpha.Square()
	beta := alpha2.Mul(alpha)
	alpha4 := alpha2.Square()
	running := E{}
	weight = one
	for _, e := range evals {
		own := e[0].Add(alpha.Mul(e[1])).Add(alpha2.Mul(e[2])).Add(beta)
		running = running.Add(weight.Mul(own))
		weight = weight.Mul(alpha4)
	}
	rounds := make([]E, maxRest)
	for i := range rounds {
		running, rounds[i] = r.round(running, nil)
		if r.Err != nil {
			return nil, r.Err
		}
	}
	waits := make([]E, maxRest+1)
	waits[maxRest] = one
	for i := maxRest - 1; i >= 0; i-- {
		waits[i] = waits[i+1].Mul(rounds[i])
	}
	out := make([]Replay, len(shapes))
	total := E{}
	weight = one
	for i, s := range shapes {
		rest := s.KLog - 6
		parts := r.Elements(64, false)
		value := r.ReadElement()
		if r.Err != nil {
			return nil, r.Err
		}
		cols := slices.Clone(rounds[:rest])
		slices.Reverse(cols)
		rows := slices.Clone(mlv[:rest])
		pin := parts[s.Pin&63].Mul(field.EqBits(uint64(s.Pin>>6), cols))
		own := value.Add(beta.Mul(pin)).Add(alpha2.Mul(field.Eq(rows, cols).Mul(lagrangeAt(z, vanish, parts))))
		total = total.Add(weight.Mul(waits[rest]).Mul(own))
		weight = weight.Mul(alpha4)
		point := append(slices.Clone(cols), mlv[rest:s.KLog+s.LogInstances-6]...)
		out[i] = Replay{Claim: pcs.SliceClaim{Point: point, Slices: parts}, Matrix: MatrixClaim{Alpha: alpha, Skip: z, Value: value, Rows: rows, Cols: cols, Slices: parts}}
	}
	if r.Err != nil {
		return nil, r.Err
	}
	if total != running {
		return nil, ErrReduction
	}
	return out, nil
}

const machineMaxK = 14

// Check settles the returned matrix claim against the authenticated circuit.
func (m MatrixClaim) Check(c *machine.Circuit, scratch []E) error {
	if len(m.Slices) != 64 || len(m.Rows) != c.KLog-6 || len(m.Cols) != c.KLog-6 {
		return ErrReduction
	}
	weights := lagrangeWeights(m.Skip)
	rows, cols := field.EqTable(m.Rows), field.EqTable(m.Cols)
	row := func(i int) E { return weights[i&63].Mul(rows[i>>6]) }
	col := func(i int) E { return m.Slices[i&63].Mul(cols[i>>6]) }
	got, err := c.Bilinear(m.Alpha, row, col, scratch)
	if err != nil {
		return err
	}
	if got != m.Value {
		return ErrReduction
	}
	return nil
}
