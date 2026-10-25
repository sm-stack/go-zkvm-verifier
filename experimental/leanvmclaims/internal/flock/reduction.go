// CREDIT: https://github.com/succinctlabs/flock, MIT OR Apache-2.0.
// Port of flock reduction, zerocheck and lincheck at da5c964831c993b011464e4fd4a573b7172d5295.
package flock

import (
	"encoding/binary"
	"errors"
	"slices"

	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/field"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/machine"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/pcs"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
)

type E = field.Element

var one = field.One
var ErrReduction = errors.New("mixed: flock reduction mismatch")

type Shape struct{ KLog, Pin, LogInstances int }
type MatrixClaim struct {
	Alpha, Skip, Value E
	Rows, Cols, Slices []E
}
type Replay struct {
	Claim  pcs.SliceClaim
	Matrix MatrixClaim
}

type reader struct {
	v   *transcript.Verifier
	err error
}

func (r *reader) element(draw bool) E {
	if r.err != nil {
		return E{}
	}
	var b []byte
	if draw {
		b = make([]byte, 24)
		r.err = r.v.Draw(b)
	} else {
		b, r.err = r.v.Read(24)
	}
	if r.err != nil {
		return E{}
	}
	return E{C0: binary.LittleEndian.Uint64(b), C1: binary.LittleEndian.Uint64(b[8:]), C2: binary.LittleEndian.Uint64(b[16:])}
}
func (r *reader) read() E { return r.element(false) }
func (r *reader) draw() E { return r.element(true) }
func (r *reader) many(n int, draw bool) []E {
	out := make([]E, n)
	for i := range out {
		out[i] = r.element(draw)
	}
	return out
}
func (r *reader) round(claim E, eq *E) (E, E) {
	a, b := r.read(), r.read()
	c := a
	if eq == nil {
		a = claim.Add(b)
	} else {
		c = claim.Add(eq.Mul(a.Add(b)))
	}
	x := r.draw()
	return c.Add(x.Mul(a.Add(x.Mul(b)))), x
}
func eqBits(index int, point []E) E {
	out := one
	for i, x := range point {
		if index>>uint(i)&1 == 0 {
			x = x.Add(one)
		}
		out = out.Mul(x)
	}
	return out
}
func eqEval(a, b []E) E {
	out := one
	for i, x := range a {
		out = out.Mul(one.Add(x).Add(b[i]))
	}
	return out
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
	r := reader{v: v}
	outer := r.many(maxM-13, true)
	lambda := r.draw()
	round1 := r.many(64, false)
	z := r.draw()
	if r.err != nil {
		return nil, r.err
	}
	vanish := vanishing(z, 64)
	claim := firstRound(z, vanish, round1)
	coordinates := append(slices.Clone(fixedChallenges[:]), outer...)
	mlv := make([]E, len(coordinates))
	for i, eq := range coordinates {
		claim, mlv[i] = r.round(claim, &eq)
		if r.err != nil {
			return nil, r.err
		}
	}
	evals := make([][3]E, len(shapes))
	terminal, weight := E{}, one
	for i := range evals {
		a, b, c := r.read(), r.read(), r.read()
		evals[i] = [3]E{a, b, c}
		terminal = terminal.Add(weight.Mul(a.Mul(b).Add(c)))
		weight = weight.Mul(lambda)
	}
	if r.err != nil {
		return nil, r.err
	}
	if terminal != claim {
		return nil, ErrReduction
	}
	alpha := r.draw()
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
		if r.err != nil {
			return nil, r.err
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
		parts := r.many(64, false)
		value := r.read()
		if r.err != nil {
			return nil, r.err
		}
		cols := slices.Clone(rounds[:rest])
		slices.Reverse(cols)
		rows := slices.Clone(mlv[:rest])
		pin := parts[s.Pin&63].Mul(eqBits(s.Pin>>6, cols))
		own := value.Add(beta.Mul(pin)).Add(alpha2.Mul(eqEval(rows, cols).Mul(lagrangeAt(z, vanish, parts))))
		total = total.Add(weight.Mul(waits[rest]).Mul(own))
		weight = weight.Mul(alpha4)
		point := append(slices.Clone(cols), mlv[rest:s.KLog+s.LogInstances-6]...)
		out[i] = Replay{Claim: pcs.SliceClaim{Point: point, Slices: parts}, Matrix: MatrixClaim{Alpha: alpha, Skip: z, Value: value, Rows: rows, Cols: cols, Slices: parts}}
	}
	if r.err != nil {
		return nil, r.err
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
	row := func(i int) E { return weights[i&63].Mul(eqBits(i>>6, m.Rows)) }
	col := func(i int) E { return m.Slices[i&63].Mul(eqBits(i>>6, m.Cols)) }
	got, err := c.Bilinear(m.Alpha, row, col, scratch)
	if err != nil {
		return err
	}
	if got != m.Value {
		return ErrReduction
	}
	return nil
}
