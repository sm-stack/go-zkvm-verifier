// CREDIT: https://github.com/succinctlabs/flock (flock-core), MIT OR Apache-2.0.
// Port of pcs/src/{stack/mod,ring_switch}.rs at da5c964831c993b011464e4fd4a573b7172d5295.
package pcs

import (
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/field"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
)

// PointClaim represents both plain and strided claims. A plain claim has
// StrideLog=0 and Slot=0. Offset and stride describe the committed word indices.
type PointClaim struct {
	Offset    uint64
	Slot      uint64
	StrideLog int
	Point     []E
	Value     E
}
type SliceClaim struct {
	Point  []E
	Slices []E
}
type RingClaim struct {
	Offset uint64
	Vars   int
	Claims []SliceClaim
}

func aligned(offset uint64, vars int, committed uint64) bool {
	if vars < 0 || vars > 63 {
		return false
	}
	n := uint64(1) << uint(vars)
	return offset%n == 0 && offset <= committed && n <= committed-offset
}
func (p PointClaim) valid(committed uint64) bool {
	if p.StrideLog < 0 || p.StrideLog > 63 || len(p.Point) > 63-p.StrideLog {
		return false
	}
	return p.Slot < uint64(1)<<uint(p.StrideLog) && aligned(p.Offset, p.StrideLog+len(p.Point), committed)
}
func (p PointClaim) at(x []E) E {
	s, n := p.StrideLog, p.StrideLog+len(p.Point)
	return eqBits(p.Slot, x[:s]).Mul(eq(p.Point, x[s:n])).Mul(eqBits(p.Offset>>uint(n), x[n:]))
}
func inverseLadder(v E, lowest int) [64]E {
	var out [64]E
	for i := range out {
		out[i] = v
	}
	power := v.Frobenius64().Frobenius64()
	for i := 63; i >= max(1, lowest); i-- {
		power = power.Square()
		out[i] = power
	}
	return out
}

var compositionShifts = [6]int{32, 16, 8, 4, 2, 1}

type ringFamily struct {
	gamma        E
	challenges   [6]E
	coefficients [64]E
}

func drawFamily(r *reader) ringFamily {
	f := ringFamily{gamma: r.draw()}
	for i := range f.challenges {
		f.challenges[i] = r.draw()
	}
	f.coefficients[0] = one
	indices := []int{0}
	for i, shift := range compositionShifts {
		ladder := inverseLadder(f.challenges[i], shift)
		n := len(indices)
		for _, k := range indices[:n] {
			f.coefficients[k+shift] = f.coefficients[k].Mul(ladder[k+shift])
			indices = append(indices, k+shift)
		}
	}
	return f
}
func (f ringFamily) apply(v E) E {
	for i, shift := range compositionShifts {
		power := v
		for range shift {
			power = power.Square()
		}
		v = v.Add(f.challenges[i].Mul(power))
	}
	return v
}
func closeTerms(terms [64]E) E {
	v := terms[63]
	for i := 62; i >= 0; i-- {
		v = v.Square().Add(terms[i])
	}
	return v
}
func (f ringFamily) target(rings []RingClaim) E {
	var family [64]E
	scale := one
	for _, ring := range rings {
		for _, claim := range ring.Claims {
			for i, s := range claim.Slices {
				family[i] = family[i].Add(scale.Mul(s))
			}
			scale = scale.Mul(f.gamma)
		}
	}
	var target E
	for i, s := range family {
		target = target.Add(f.apply(s).MulBase(uint64(1) << uint(i)))
	}
	return target
}
func (f ringFamily) at(rings []RingClaim, x []E) E {
	longest := 0
	for _, ring := range rings {
		longest = max(longest, ring.Vars)
	}
	ladders := make([][64]E, longest)
	for i := range ladders {
		ladders[i] = inverseLadder(x[i], 1)
	}
	scale := one
	var weight E
	for _, ring := range rings {
		var sum [64]E
		for _, claim := range ring.Claims {
			for k, c := range f.coefficients {
				term := c
				for n, z := range claim.Point {
					term = term.Mul(one.Add(z).Add(ladders[n][k]))
				}
				sum[k] = sum[k].Add(scale.Mul(term))
			}
			scale = scale.Mul(f.gamma)
		}
		weight = weight.Add(closeTerms(sum).Mul(eqBits(ring.Offset>>uint(ring.Vars), x[ring.Vars:])))
	}
	return weight
}

// VerifyStack verifies a plain stack opening. All claim values, points, and bit
// slices must already be bound by the caller's transcript or trusted instance.
// This method does not authenticate a claim merely because it was supplied here.
func VerifyStack(v *transcript.Verifier, root [32]byte, logN, rate, lanes int, points []PointClaim, rings []RingClaim) error {
	c, e := configFor(logN, rate)
	if e != nil {
		return e
	}
	if lanes < 1 || lanes > 1<<uint(c.initialK) {
		return ErrOpening
	}
	committed := uint64(lanes) << uint(logN-c.initialK)
	hasClaim := len(points) > 0
	for _, p := range points {
		if !p.valid(committed) {
			return ErrOpening
		}
	}
	for _, ring := range rings {
		if ring.Vars > logN || !aligned(ring.Offset, ring.Vars, committed) {
			return ErrOpening
		}
		for _, claim := range ring.Claims {
			if len(claim.Point) != ring.Vars || len(claim.Slices) != 64 {
				return ErrOpening
			}
			hasClaim = true
		}
	}
	if !hasClaim {
		return ErrOpening
	}
	r := reader{v: v}
	family := drawFamily(&r)
	lambda := r.draw()
	weights := powers(lambda, len(points)+1)
	if r.err != nil {
		return r.err
	}
	target := family.target(rings)
	for i, p := range points {
		target = target.Add(weights[i+1].Mul(p.Value))
	}
	return verifyWHIR(v, root, logN, rate, lanes, target, func(x []field.Element) E {
		weight := family.at(rings, x)
		for i, p := range points {
			weight = weight.Add(weights[i+1].Mul(p.at(x)))
		}
		return weight
	})
}
