// CREDIT: https://github.com/succinctlabs/flock (skip-domain Lagrange weights), MIT OR Apache-2.0.
package flock

import "github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/field"

// phi_8 basis from primitives/src/field/gf2_8.rs at the pinned revision.
var phiBasis = [8]uint64{1, 0x033ce8beddc8a656, 0x512620375ed2a108, 0x0c9e636090aafc01, 0xba4f3cd82801769c, 0xba26e7904adb4a47, 0x467698598926dc01, 0x4418ae808b28bdd0}

func phi(i int) E {
	var x uint64
	for j, b := range phiBasis {
		if i>>uint(j)&1 != 0 {
			x ^= b
		}
	}
	return field.Lift(x)
}

var fixedChallenges = func() (out [7]E) {
	out[0], out[1], out[2] = phi(0xf7), phi(0x53), phi(0xb5)
	g := E{C0: 0x243f6a8885a308d3, C1: 0x13198a2e03707344, C2: 0xa4093822299f31d0}
	for i := 3; i < 7; i++ {
		out[i] = g.Mul(one.Add(g).Inv())
		g = g.Square()
	}
	return
}()
var denominators = func() (out [2]E) {
	p := one
	for i := 1; i < 128; i++ {
		p = p.Mul(phi(i))
		if i == 63 {
			out[0] = p.Inv()
		}
	}
	out[1] = p.Inv()
	return
}()

func vanishing(z E, n int) E {
	out := one
	for i := 0; i < n; i++ {
		out = out.Mul(z.Add(phi(i)))
	}
	return out
}
func firstRound(z, vanish E, values []E) E {
	offset := vanishing(phi(64), 64)
	scale := vanish.Mul(vanish.Add(offset)).Mul(denominators[1])
	sum := E{}
	for i, v := range values {
		sum = sum.Add(v.Mul(z.Add(phi(64 + i)).Inv()))
	}
	return scale.Mul(sum)
}
func lagrangeAt(z, vanish E, values []E) E {
	sum := E{}
	for i, v := range values {
		sum = sum.Add(v.Mul(z.Add(phi(i)).Inv()))
	}
	return vanish.Mul(denominators[0]).Mul(sum)
}
func lagrangeWeights(z E) [64]E {
	var out [64]E
	p := denominators[0]
	for i := range out {
		out[i] = p
		p = p.Mul(z.Add(phi(i)))
	}
	p = one
	for i := 63; i >= 0; i-- {
		out[i] = out[i].Mul(p)
		p = p.Mul(z.Add(phi(i)))
	}
	return out
}
