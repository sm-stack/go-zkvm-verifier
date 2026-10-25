// Port of pinned fiat_shamir::arith and gkr verifier operations. See NOTICE.
package recursion

import (
	"errors"
	"fmt"

	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/field"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
)

type E = field.Element

var one = field.One
var ErrProof = errors.New("leanvmclaims: recursion proof mismatch")

var ErrGKROdd = fmt.Errorf("%w: GKR odd layer", ErrProof)
var ErrGKRQuad = fmt.Errorf("%w: GKR radix-4 layer", ErrProof)

type reader struct{ transcript.FieldReader }

func (r *reader) round(n int, claim E, eq *E) (E, E) {
	sent := r.Elements(n-1, false)
	c := make([]E, n)
	if eq != nil {
		copy(c[1:], sent)
		sum := E{}
		for _, x := range sent {
			sum = sum.Add(x)
		}
		c[0] = claim.Add(eq.Mul(sum))
	} else {
		c[0] = sent[0]
		copy(c[2:], sent[1:])
		c[1] = claim
		for _, x := range sent[1:] {
			c[1] = c[1].Add(x)
		}
	}
	x := r.DrawElement()
	return poly(c, x), x
}
func poly(c []E, x E) E {
	out := E{}
	for i := len(c) - 1; i >= 0; i-- {
		out = out.Mul(x).Add(c[i])
	}
	return out
}
func interp(a, b, x E) E    { return a.Add(x.Mul(a.Add(b))) }
func element(w [3]uint64) E { return E{C0: w[0], C1: w[1], C2: w[2]} }
func intIndex(base uint64, point []E) E {
	out := field.Lift(base)
	for i, x := range point {
		out = out.Add(x.MulBase(uint64(1) << uint(i)))
	}
	return out
}

func products(r *reader, mu int) ([]E, [2]E, error) {
	root := r.ReadElement()
	lambda := r.DrawElement()
	point := []E{}
	values := [2]E{root, root}
	for layer := mu; layer > 0; {
		claim := values[0].Add(lambda.Mul(values[1]))
		if layer%2 == 1 {
			var children [2][2]E
			for i := range children {
				for j := range children[i] {
					children[i][j] = r.ReadElement()
				}
			}
			expected := children[0][0].Mul(children[0][1]).Add(lambda.Mul(children[1][0].Mul(children[1][1])))
			if r.Err != nil {
				return nil, values, r.Err
			}
			if expected != claim {
				return nil, values, ErrGKROdd
			}
			x := r.DrawElement()
			for i := range values {
				values[i] = interp(children[i][0], children[i][1], x)
			}
			lambda = r.DrawElement()
			point = []E{x}
			layer--
			continue
		}
		challenges := make([]E, len(point))
		for i, eq := range point {
			claim, challenges[i] = r.round(5, claim, &eq)
			if r.Err != nil {
				return nil, values, r.Err
			}
		}
		var children [2][4]E
		var prods [2]E
		for i := range children {
			prods[i] = one
			for j := range children[i] {
				children[i][j] = r.ReadElement()
				prods[i] = prods[i].Mul(children[i][j])
			}
		}
		if r.Err != nil {
			return nil, values, r.Err
		}
		if prods[0].Add(lambda.Mul(prods[1])) != claim {
			return nil, values, ErrGKRQuad
		}
		low, high := r.DrawElement(), r.DrawElement()
		for i, c := range children {
			values[i] = interp(interp(c[0], c[1], low), interp(c[2], c[3], low), high)
		}
		lambda = r.DrawElement()
		point = append([]E{low, high}, challenges...)
		layer -= 2
	}
	return point, values, r.Err
}
