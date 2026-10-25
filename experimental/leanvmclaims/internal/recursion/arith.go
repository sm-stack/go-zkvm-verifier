// Port of pinned fiat_shamir::arith and gkr verifier operations. See NOTICE.
package recursion

import (
	"encoding/binary"
	"errors"

	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/field"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
)

type E = field.Element

var one = field.One
var ErrProof = errors.New("mixed: recursion proof mismatch")

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
func (r *reader) round(n int, claim E, eq *E) (E, E) {
	sent := r.many(n-1, false)
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
	x := r.draw()
	return poly(c, x), x
}
func poly(c []E, x E) E {
	out := E{}
	for i := len(c) - 1; i >= 0; i-- {
		out = out.Mul(x).Add(c[i])
	}
	return out
}
func interp(a, b, x E) E { return a.Add(x.Mul(a.Add(b))) }
func eqBits(index uint64, point []E) E {
	out := one
	for i, x := range point {
		if index>>uint(i)&1 == 0 {
			x = x.Add(one)
		}
		out = out.Mul(x)
	}
	return out
}
func eqTable(point []E) []E {
	out := make([]E, 1, 1<<uint(len(point)))
	out[0] = one
	for _, x := range point {
		n := len(out)
		out = out[:n*2]
		for i := 0; i < n; i++ {
			hi := out[i].Mul(x)
			out[n+i] = hi
			out[i] = out[i].Add(hi)
		}
	}
	return out
}
func element(w [3]uint64) E { return E{C0: w[0], C1: w[1], C2: w[2]} }
func intIndex(base uint64, point []E) E {
	out := field.Lift(base)
	for i, x := range point {
		out = out.Add(x.MulBase(uint64(1) << uint(i)))
	}
	return out
}

func products(r *reader, mu int) ([]E, [2]E, error) {
	root := r.read()
	lambda := r.draw()
	point := []E{}
	values := [2]E{root, root}
	for layer := mu; layer > 0; {
		claim := values[0].Add(lambda.Mul(values[1]))
		if layer%2 == 1 {
			var children [2][2]E
			for i := range children {
				for j := range children[i] {
					children[i][j] = r.read()
				}
			}
			expected := children[0][0].Mul(children[0][1]).Add(lambda.Mul(children[1][0].Mul(children[1][1])))
			if r.err != nil {
				return nil, values, r.err
			}
			if expected != claim {
				return nil, values, ErrProof
			}
			x := r.draw()
			for i := range values {
				values[i] = interp(children[i][0], children[i][1], x)
			}
			lambda = r.draw()
			point = []E{x}
			layer--
			continue
		}
		challenges := make([]E, len(point))
		for i, eq := range point {
			claim, challenges[i] = r.round(5, claim, &eq)
			if r.err != nil {
				return nil, values, r.err
			}
		}
		var children [2][4]E
		var prods [2]E
		for i := range children {
			prods[i] = one
			for j := range children[i] {
				children[i][j] = r.read()
				prods[i] = prods[i].Mul(children[i][j])
			}
		}
		if r.err != nil {
			return nil, values, r.err
		}
		if prods[0].Add(lambda.Mul(prods[1])) != claim {
			return nil, values, ErrProof
		}
		low, high := r.draw(), r.draw()
		for i, c := range children {
			values[i] = interp(interp(c[0], c[1], low), interp(c[2], c[3], low), high)
		}
		lambda = r.draw()
		point = append([]E{low, high}, challenges...)
		layer -= 2
	}
	return point, values, r.err
}
