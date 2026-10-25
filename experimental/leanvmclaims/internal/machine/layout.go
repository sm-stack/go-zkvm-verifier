// Derived from rec/layout.rs, rec/fixed.rs and stacking.rs at the pinned revision.
package machine

import (
	"errors"
	"math/bits"
	"slices"
)

var ErrLayout = errors.New("leanvmclaims: unsupported or malformed layout")

// Placement is a committed window (Kind=0) or a port of the packed hash witness
// (Kind=1). Ports freeze the low Stride coordinates to Slot.
type Placement struct {
	Kind               int
	Offset             uint64
	Vars, Slot, Stride int
}
type Layout struct {
	Heights    [6]int
	Placements []Placement
	Mu, Lanes  int
	FixedVars  int
}

var ownedColumns = [5]int{9, 7, 19, 65, 4}
var fixedColumns = [6]int{4, 4, 16, 65, 8, 5}

func ceilLog(n uint64) int {
	if n <= 1 {
		return 0
	}
	return bits.Len64(n - 1)
}
func offsets(kappas []int) ([]uint64, uint64) {
	order := make([]int, 0, len(kappas))
	for i, k := range kappas {
		if k >= 0 {
			order = append(order, i)
		}
	}
	slices.SortFunc(order, func(a, b int) int {
		if kappas[a] != kappas[b] {
			return kappas[b] - kappas[a]
		}
		return a - b
	})
	out := make([]uint64, len(kappas))
	var total uint64
	for _, i := range order {
		out[i] = total
		total += uint64(1) << uint(kappas[i])
	}
	return out, total
}
func NewLayout(heights [6]uint64) (*Layout, error) {
	schema, e := Load()
	if e != nil {
		return nil, e
	}
	l := &Layout{}
	for i, h := range heights {
		if h > 32 {
			return nil, ErrLayout
		}
		l.Heights[i] = int(h)
	}
	stride := schema.Circuits[schema.HashCircuit].KLog - 6
	// The class loader requires the table floor before RecLayout::from_taus.
	if l.Heights[2] < max(0, schema.MinCubeLog-schema.Circuits[schema.HashCircuit].KLog) {
		return nil, ErrLayout
	}
	kappas := []int{l.Heights[2] + stride}
	for t, n := range ownedColumns {
		for c := 0; c < n; c++ {
			k := l.Heights[t]
			if t == 2 && c < schema.HashPorts {
				k = -1
			}
			kappas = append(kappas, k)
		}
	}
	off, total := offsets(kappas)
	l.Mu = max(schema.MinMu, ceilLog(total))
	if l.Mu > schema.MaxMu {
		return nil, ErrLayout
	}
	lane := uint64(1) << uint(l.Mu-schema.InitialK)
	l.Lanes = int(max(uint64(1), (total+lane-1)/lane))
	l.Placements = make([]Placement, len(kappas))
	for i, k := range kappas {
		if k >= 0 {
			l.Placements[i] = Placement{Offset: off[i], Vars: k}
		} else {
			l.Placements[i] = Placement{Kind: 1, Offset: off[0], Slot: i - (1 + ownedColumns[0] + ownedColumns[1]), Stride: stride}
		}
	}
	var fixed []int
	for t, n := range fixedColumns {
		for range n {
			fixed = append(fixed, l.Heights[t])
		}
	}
	_, fixedSize := offsets(fixed)
	l.FixedVars = ceilLog(fixedSize)
	return l, nil
}

// LeafSize validates the leaf witness commitment's size without constructing
// program bytecode tables or allocating any witness columns.
func (s *Schema) LeafSize(logBC, logRAM, logAdvice uint64, heights [11]uint64) (int, error) {
	for i, h := range heights {
		if h < uint64(s.LeafMinHeights[i]) || h > uint64(s.MaxLogRows) {
			return 0, ErrLayout
		}
	}
	if logBC > 32 || logRAM > 32 || logAdvice > 32 {
		return 0, ErrLayout
	}
	total := 2*(uint64(1)<<uint(s.RegisterLog)) + 2*(uint64(1)<<uint(logRAM)) + 3*(uint64(1)<<uint(logAdvice)) + (uint64(1) << uint(logBC))
	for i, c := range s.Circuits {
		total += uint64(1) << uint(heights[s.CircuitTables[i]]+uint64(c.KLog-6))
	}
	for t, n := range s.LeafColumns {
		total += uint64(n) << uint(heights[t])
	}
	// Rust's RegisterWord::of: first-fit packing, equal heights only, 64 bits/word.
	type group struct {
		height uint64
		used   int
	}
	var groups []group
	for t, n := range s.RegisterBits {
		found := false
		for i, g := range groups {
			if g.height == heights[t] && g.used+n <= 64 {
				groups[i].used += n
				found = true
				break
			}
		}
		if !found {
			groups = append(groups, group{heights[t], n})
			total += uint64(1) << uint(heights[t])
		}
	}
	mu := max(s.MinMu, ceilLog(total))
	if mu > s.MaxMu {
		return 0, ErrLayout
	}
	return mu, nil
}
