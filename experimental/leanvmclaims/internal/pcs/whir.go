// CREDIT: https://github.com/succinctlabs/flock (flock-core), MIT OR Apache-2.0.
// Copyright (c) 2026 Bain Capital Crypto, LP and Ron Rothblum
// Modifications copyright 2026 Succinct Labs, Benedikt Bunz, William Wang
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Port of pcs/src/whir/verify.rs at da5c964831c993b011464e4fd4a573b7172d5295.
package pcs

import (
	"encoding/binary"
	"errors"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/field"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
	"slices"
)

type E = field.Element

var one = field.One
var ErrTerminal = errors.New("mixed: PCS terminal claim mismatch")

type reader struct {
	v   *transcript.Verifier
	err error
}

func (r *reader) fail(e error) {
	if r.err == nil {
		r.err = e
	}
}
func decodeE(b []byte) E {
	return E{C0: binary.LittleEndian.Uint64(b[:8]), C1: binary.LittleEndian.Uint64(b[8:16]), C2: binary.LittleEndian.Uint64(b[16:24])}
}
func (r *reader) read() E {
	if r.err != nil {
		return E{}
	}
	b, e := r.v.Read(24)
	if e != nil {
		r.fail(e)
		return E{}
	}
	return decodeE(b)
}
func (r *reader) draw() E {
	if r.err != nil {
		return E{}
	}
	var b [24]byte
	if e := r.v.Draw(b[:]); e != nil {
		r.fail(e)
		return E{}
	}
	return decodeE(b[:])
}
func (r *reader) draws(n int) []E {
	out := make([]E, n)
	for i := range out {
		out[i] = r.draw()
	}
	return out
}
func (r *reader) reads(n int) []E {
	out := make([]E, n)
	for i := range out {
		out[i] = r.read()
	}
	return out
}
func (r *reader) root() [32]byte {
	var out [32]byte
	if r.err != nil {
		return out
	}
	b, e := r.v.Read(32)
	if e != nil {
		r.fail(e)
	} else {
		copy(out[:], b)
	}
	return out
}

type quad struct{ c, b, a E }

func (r *reader) quad(claim E) quad { c, a := r.read(), r.read(); return quad{c, claim.Add(a), a} }
func (q quad) at(x E) E             { return q.a.Mul(x).Add(q.b).Mul(x).Add(q.c) }
func (q quad) fold(other quad, s E) quad {
	return quad{q.c.Add(other.c.Mul(s)), q.b.Add(other.b.Mul(s)), q.a.Add(other.a.Mul(s))}
}
func eq(a, b []E) E {
	v := one
	for i, x := range a {
		v = v.Mul(one.Add(x).Add(b[i]))
	}
	return v
}
func eqBits(index uint64, point []E) E {
	v := one
	for i, x := range point {
		if index>>uint(i)&1 == 0 {
			x = x.Add(one)
		}
		v = v.Mul(x)
	}
	return v
}
func eqPrefix(point []E, n int) []E {
	out := make([]E, n)
	for i := range out {
		out[i] = eqBits(uint64(i), point)
	}
	return out
}
func powers(x E, n int) []E {
	out := make([]E, n)
	p := one
	for i := range out {
		out[i] = p
		p = p.Mul(x)
	}
	return out
}
func mle(table, point []E) E {
	cur := slices.Clone(table)
	for _, x := range point {
		for i := 0; i < len(cur)/2; i++ {
			a, b := cur[2*i], cur[2*i+1]
			cur[i] = a.Add(x.Mul(a.Add(b)))
		}
		cur = cur[:len(cur)/2]
	}
	return cur[0]
}

// The native verifier only needs s_k(v_k) and its inverse, not the dense basis.
type novelBasis struct{ normalizers, inverses []uint64 }

func newBasis(n int) novelBasis {
	row := make([]uint64, n+1)
	for i := range row {
		row[i] = uint64(1) << uint(i)
	}
	b := novelBasis{make([]uint64, n+1), make([]uint64, n+1)}
	for k := 0; k <= n; k++ {
		norm := row[0]
		b.normalizers[k] = norm
		b.inverses[k] = field.Inv64(norm)
		for i := 0; i < len(row)-1; i++ {
			s := row[i+1]
			row[i] = field.Mul64(s, s^norm)
		}
		row = row[:len(row)-1]
	}
	return b
}
func (b novelBasis) next(s E, k int) E { return s.Square().Add(s.MulBase(b.normalizers[k])) }

type ood struct {
	z     []E
	y     E
	intro quad
}
type oodContext struct {
	z     []E
	start int
	beta  E
}
type levelContext struct {
	n       int
	queries []uint64
	weights []E
	start   int
	beta    E
}
type oracle struct {
	root       [32]byte
	k, n, rate int
}

func (o oracle) depth() int { return o.n + o.rate }

type replay struct {
	reader
	config config
	target E
	quad   quad
	ris    []E
	levels []levelContext
	oods   []oodContext
}

func (w *replay) challenge() E {
	x := w.draw()
	w.target = w.quad.at(x)
	w.ris = append(w.ris, x)
	return x
}
func (w *replay) folds(k int) []E {
	rs := make([]E, k)
	for i := range rs {
		rs[i] = w.challenge()
		w.quad = w.reader.quad(w.target)
	}
	return rs
}
func (w *replay) readOOD(level, n int) []ood {
	out := make([]ood, w.config.oods[level])
	for i := range out {
		z := w.draws(n)
		y := w.read()
		out[i] = ood{z, y, w.reader.quad(y)}
	}
	return out
}
func (w *replay) nextOracle(root [32]byte, level, n int) oracle {
	k := w.config.levelKs[level]
	if n < k {
		w.fail(ErrOpening)
		return oracle{}
	}
	return oracle{root, k, n - k, w.config.rates[level+1]}
}
func (w *replay) rows(o oracle, queries []uint64) [][]E {
	width := 1 << uint(o.k)
	words, e := ReadRows(w.v, o.root, o.depth(), queries, 3*width, 3*width)
	if e != nil {
		w.fail(e)
		return nil
	}
	out := make([][]E, len(words))
	for i, row := range words {
		out[i] = make([]E, width)
		for j := range out[i] {
			out[i][j] = E{C0: row[3*j], C1: row[3*j+1], C2: row[3*j+2]}
		}
	}
	return out
}
func sumRows(rows [][]E, point, weights []E) E {
	var out E
	if len(rows) == 0 {
		return out
	}
	factors := eqPrefix(point, len(rows[0]))
	for i, row := range rows {
		var inner E
		for j, x := range row {
			inner = inner.Add(x.Mul(factors[j]))
		}
		out = out.Add(inner.Mul(weights[i]))
	}
	return out
}
func (w *replay) query(level, depth, n int, oods []ood, enforced func([]uint64, []E) E) {
	if w.err != nil {
		return
	}
	if e := w.v.CheckPOW(uint32(w.config.grinding[level])); e != nil {
		w.fail(e)
		return
	}
	queries, e := SampleQueries(w.v, depth, w.config.queries[level])
	if e != nil {
		w.fail(e)
		return
	}
	lambda := w.draw()
	weights := powers(lambda, len(queries))
	sum := enforced(queries, weights)
	if w.err != nil {
		return
	}
	intro := w.reader.quad(sum)
	scalar := one
	start := len(w.ris)
	for _, o := range oods {
		scalar = scalar.Mul(lambda)
		w.quad = w.quad.fold(o.intro, scalar)
		w.target = w.target.Add(scalar.Mul(o.y))
		w.oods = append(w.oods, oodContext{o.z, start, scalar})
	}
	scalar = scalar.Mul(lambda)
	w.quad = w.quad.fold(intro, scalar)
	w.target = w.target.Add(scalar.Mul(sum))
	w.levels = append(w.levels, levelContext{n, queries, weights, start, scalar})
}
func (c levelContext) basisAt(point []E) E {
	basis := newBasis(c.n)
	var out E
	for i, q := range c.queries {
		s := field.Lift(q)
		product := one
		for k, p := range point {
			if k > 0 {
				s = basis.next(s, k-1)
			}
			product = product.Mul(one.Add(p).Add(p.MulBase(basis.inverses[k]).Mul(s)))
		}
		out = out.Add(product.Mul(c.weights[i]))
	}
	return out
}
func (w *replay) terminal(yr, tail []E, weightAt func([]E) E) error {
	if w.err != nil {
		return w.err
	}
	var weight E
	for _, c := range w.levels {
		folded := c.n - len(tail)
		if folded < 0 || c.start+folded > len(w.ris) {
			return ErrOpening
		}
		point := append(slices.Clone(w.ris[c.start:c.start+folded]), tail...)
		weight = weight.Add(c.beta.Mul(c.basisAt(point)))
	}
	for _, c := range w.oods {
		folded := len(c.z) - len(tail)
		if folded < 0 || c.start+folded > len(w.ris) {
			return ErrOpening
		}
		point := append(slices.Clone(w.ris[c.start:c.start+folded]), tail...)
		weight = weight.Add(c.beta.Mul(eq(c.z, point)))
	}
	point := append(slices.Clone(w.ris), tail...)
	k := w.config.initialK
	point = append(slices.Clone(point[k:]), point[:k]...)
	weight = weight.Add(weightAt(point))
	if weight.Mul(mle(yr, tail)) != w.target {
		return ErrTerminal
	}
	return nil
}

// verifyWHIR verifies a plain commitment under the pinned production profile.
// The caller must bind both target and weight to its transcript before this call.
func verifyWHIR(v *transcript.Verifier, root [32]byte, logN, rate, lanes int, target E, weightAt func([]E) E) error {
	c, e := configFor(logN, rate)
	if e != nil {
		return e
	}
	maxLanes := 1 << uint(c.initialK)
	if lanes < 1 || lanes > maxLanes {
		return ErrOpening
	}
	w := replay{reader: reader{v: v}, config: c, target: target}
	w.quad = w.reader.quad(target)
	n := logN - c.initialK
	laneFold := w.folds(c.initialK - 1)
	laneFold = append(laneFold, w.challenge())
	w.quad = w.reader.quad(w.target)
	nextRoot := w.root()
	oods := w.readOOD(1, n)
	w.query(0, n+c.rates[0], n, oods, func(queries []uint64, weights []E) E {
		rows, e := ReadRows(v, root, n+c.rates[0], queries, lanes, maxLanes)
		if e != nil {
			w.fail(e)
			return E{}
		}
		factors := eqPrefix(laneFold, lanes)
		var sum E
		for i, row := range rows {
			slices.Reverse(row)
			var inner E
			for j, x := range row {
				inner = inner.Add(factors[j].MulBase(x))
			}
			sum = sum.Add(weights[i].Mul(inner))
		}
		return sum
	})
	if w.err != nil {
		return w.err
	}
	o := w.nextOracle(nextRoot, 0, n)
	for i, k := range c.levelKs {
		rs := w.folds(k)
		n -= k
		if w.err != nil {
			return w.err
		}
		if i+1 == len(c.levelKs) {
			yr := w.reads(1 << uint(n))
			w.query(len(c.levelKs), o.depth(), n, nil, func(queries []uint64, weights []E) E { return sumRows(w.rows(o, queries), rs, weights) })
			tail := make([]E, n)
			for j := range tail {
				tail[j] = w.draw()
				w.target = w.quad.at(tail[j])
				if j+1 < n {
					w.quad = w.reader.quad(w.target)
				}
			}
			return w.terminal(yr, tail, weightAt)
		}
		nextRoot = w.root()
		oods = w.readOOD(i+2, n)
		w.query(i+1, o.depth(), n, oods, func(queries []uint64, weights []E) E { return sumRows(w.rows(o, queries), rs, weights) })
		if w.err != nil {
			return w.err
		}
		o = w.nextOracle(nextRoot, i+1, n)
	}
	return ErrOpening
}
