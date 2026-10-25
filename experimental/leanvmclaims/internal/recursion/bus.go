// Recursion-only specialization of pinned bus::{verify_balance,decompose}.
// No producer, sparse, or externally committed framework column occurs here.
package recursion

import (
	"math/bits"
	"slices"

	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/classkey"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/machine"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/wire"
)

type product struct {
	a, b   int
	weight E
}
type form struct {
	coeffs   []E
	prods    []product
	constant E
}

func (f *form) add(src machine.Form, weight E) {
	f.constant = f.constant.Add(element(src.Constant).Mul(weight))
	for i, c := range src.Coeffs {
		if c != [3]uint64{} {
			f.coeffs[i] = f.coeffs[i].Add(element(c).Mul(weight))
		}
	}
	for _, p := range src.Prods {
		f.prods = append(f.prods, product{p.A, p.B, element(p.Value).Mul(weight)})
	}
}
func (f form) value(cols []E) E {
	out := f.constant
	for i, c := range f.coeffs {
		out = out.Add(c.Mul(cols[i]))
	}
	for _, p := range f.prods {
		out = out.Add(p.weight.Mul(cols[p.a]).Mul(cols[p.b]))
	}
	return out
}
func identity(f machine.Form, cols []E) E {
	out := element(f.Constant)
	for i, c := range f.Coeffs {
		if c != [3]uint64{} {
			out = out.Add(element(c).Mul(cols[i]))
		}
	}
	for _, p := range f.Prods {
		out = out.Add(element(p.Value).Mul(cols[p.A]).Mul(cols[p.B]))
	}
	return out
}

type block struct {
	table, slot, global, height int
	offset                      uint64
}

type busResult struct {
	point  []E
	forms  [2][]form
	totals [2]E
}

func bus(r *reader, k *classkey.Validated, root wire.Root, position int, layout *machine.Layout, s *machine.Schema) (busResult, error) {
	var out busResult
	// Public slot first, then each owned slot: this order fixes equal-size ties.
	blocks := []block{{table: 5, global: 97, height: layout.Heights[5]}}
	global := 0
	for t, table := range s.RecTables {
		for slot := range table.Slots {
			blocks = append(blocks, block{table: t, slot: slot, global: global, height: layout.Heights[t]})
			global++
		}
	}
	order := make([]int, len(blocks))
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, func(a, b int) int {
		if blocks[a].height != blocks[b].height {
			return blocks[b].height - blocks[a].height
		}
		return a - b
	})
	var total uint64
	for _, i := range order {
		blocks[i].offset = total
		total += uint64(1) << uint(blocks[i].height)
	}
	mu := bits.Len64(total - 1)
	degree := 4*total + 8*uint64(mu+1)*uint64(mu+1)
	if 192-bits.Len64(degree) < 140 {
		return out, ErrProof
	} // 128 security + 12 list bits.
	weights := eqTable(r.many(4, true))
	beta := r.draw()
	point, values, err := products(r, mu)
	if err != nil {
		return out, err
	}
	out.point = point
	// The class key owns all public columns; no proof-supplied evaluation is trusted.
	eqs := make(map[int][]E)
	fixed := make(map[int]E)
	public := func(column, height int, statement bool) (E, error) {
		if value, ok := fixed[column]; ok {
			return value, nil
		}
		eq, ok := eqs[height]
		if !ok {
			eq = eqTable(point[:height])
			eqs[height] = eq
		}
		value := E{}
		for row, weight := range eq {
			word, err := k.Key.Word(position, column, row)
			if err != nil {
				return E{}, err
			}
			if statement && row < len(root.Words) {
				j := column - 98
				word = 0
				if j < 3 {
					word = root.Words[row][j]
				}
			}
			value = value.Add(weight.MulBase(word))
		}
		fixed[column] = value
		return value, nil
	}
	for side := 0; side < 2; side++ {
		out.forms[side] = make([]form, 5)
		for t, table := range s.RecTables {
			out.forms[side][t].coeffs = make([]E, table.Columns)
		}
		acc, padding := E{}, one
		for _, b := range blocks {
			selector := eqBits(b.offset>>uint(b.height), point[b.height:])
			padding = padding.Add(selector)
			var key E
			if side == 0 {
				key, err = public(b.global, b.height, false)
				if err != nil {
					return out, err
				}
			} else {
				key = intIndex(uint64(b.global)<<32, point[:b.height])
			}
			known := weights[0].Mul(key)
			if b.table == 5 {
				leaf := beta.Add(known)
				for j := 0; j < 4; j++ {
					value, err := public(98+j, b.height, true)
					if err != nil {
						return out, err
					}
					leaf = leaf.Add(weights[j+1].Mul(value))
				}
				acc = acc.Add(selector.Mul(leaf))
				continue
			}
			f := &out.forms[side][b.table]
			f.constant = f.constant.Add(selector.Mul(beta))
			for j, limb := range s.RecTables[b.table].Slots[b.slot] {
				f.add(limb, selector.Mul(weights[j+1]))
			}
			acc = acc.Add(selector.Mul(known))
		}
		out.totals[side] = values[side].Add(acc).Add(padding)
	}
	return out, r.err
}
