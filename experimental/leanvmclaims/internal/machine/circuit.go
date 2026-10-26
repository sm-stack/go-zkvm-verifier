// Circuit representation follows pinned leanVM crates/flock/src/circuit.rs.
// Source and license attribution: NOTICE and tools/leanvm-mixed/exporter/.
package machine

import (
	_ "embed"
	"encoding/json"
	"errors"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/field"
	"sync"
)

//go:embed metadata.json
var metadata []byte

type Circuit struct {
	Index      int         `json:"index"`
	KLog       int         `json:"k_log"`
	ConstPos   int         `json:"const_pos"`
	UsefulBits int         `json:"useful_bits"`
	InputWords int         `json:"input_words"`
	Gates      [][4]uint32 `json:"gates"`
}
type Schema struct {
	RecTables      []RecTable `json:"rec_tables"`
	LeafColumns    []int      `json:"leaf_columns"`
	RegisterBits   []int      `json:"register_bits"`
	CircuitTables  []int      `json:"circuit_tables"`
	MinBytecode    int        `json:"min_bytecode"`
	RegisterLog    int        `json:"register_log"`
	MinCubeLog     int        `json:"min_cube_log"`
	InitialK       int        `json:"initial_k"`
	Pin            string     `json:"upstream_commit"`
	LeafMinHeights []int      `json:"leaf_min_heights"`
	MaxLogRows     int        `json:"max_log_rows"`
	MaxMu          int        `json:"max_mu"`
	MinMu          int        `json:"min_mu"`
	TupleBits      int        `json:"tuple_bits"`
	HashCircuit    int        `json:"hash_circuit"`
	HashPorts      int        `json:"hash_ports"`
	MaxKLog        int        `json:"max_k_log"`
	Circuits       []Circuit  `json:"circuits"`
}

// Load returns immutable process-wide circuit data. Callers must not modify it.
// No data supplied by a proof enters this cache.
func Load() (*Schema, error) { return load() }

var load = sync.OnceValues(func() (*Schema, error) {
	var s Schema
	if e := json.Unmarshal(metadata, &s); e != nil {
		return nil, e
	}
	if s.Pin != "3e7da4e783dad4c39115e5a231849e52cae5b22f" || len(s.LeafMinHeights) != 11 || len(s.Circuits) != 21 || len(s.LeafColumns) != 11 || len(s.RegisterBits) != 11 || len(s.CircuitTables) != 21 || s.HashCircuit < 0 || s.HashCircuit >= len(s.Circuits) {
		return nil, errors.New("leanvmclaims: invalid generated circuit metadata")
	}
	for i := range s.LeafColumns {
		if s.LeafColumns[i] < 0 || s.LeafColumns[i] > 64 || s.RegisterBits[i] < 0 || s.RegisterBits[i] > 64 || s.LeafMinHeights[i] < 0 || s.LeafMinHeights[i] > 32 {
			return nil, errors.New("leanvmclaims: invalid generated table shape")
		}
	}
	if s.RegisterLog != 6 || s.InitialK != 6 || s.MinMu != 15 || s.MaxMu != 28 || s.MinBytecode != 12 || s.MaxLogRows != 32 || s.HashPorts != 18 || s.MinCubeLog != 13 {
		return nil, errors.New("leanvmclaims: invalid generated layout constants")
	}
	for i, c := range s.Circuits {
		if s.CircuitTables[i] < 0 || s.CircuitTables[i] >= 11 || c.KLog < s.InitialK {
			return nil, errors.New("leanvmclaims: invalid generated circuit table")
		}
		if c.Index != i || c.KLog < 0 || c.KLog > 20 || c.ConstPos < 0 || c.ConstPos >= 1<<uint(c.KLog) || c.UsefulBits > 1<<uint(c.KLog) {
			return nil, errors.New("leanvmclaims: invalid generated circuit shape")
		}
		for j, g := range c.Gates {
			slot := uint32(0)
			switch g[0] {
			case 0:
				slot = g[1]
			case 1:
				if int(g[1]) >= j || int(g[2]) >= j {
					return nil, errors.New("leanvmclaims: cyclic XOR gate")
				}
				continue
			case 2:
				if int(g[1]) >= j || int(g[2]) >= j {
					return nil, errors.New("leanvmclaims: cyclic product gate")
				}
				slot = g[3]
			case 3:
				if int(g[1]) >= j {
					return nil, errors.New("leanvmclaims: cyclic copy gate")
				}
				slot = g[2]
			default:
				return nil, errors.New("leanvmclaims: unknown generated gate")
			}
			if uint64(slot) >= uint64(1)<<uint(c.KLog) {
				return nil, errors.New("leanvmclaims: generated gate slot outside circuit")
			}
		}
	}
	if err := validateTables(s.RecTables); err != nil {
		return nil, err
	}
	return &s, nil
})

// Bilinear walks A and B without materializing their matrices. Row/column are
// the evaluation weights of committed slots; scratch is private to one verify.
func (c *Circuit) Bilinear(alpha field.Element, row, column func(int) field.Element, scratch []field.Element) (field.Element, error) {
	if len(scratch) < len(c.Gates) {
		return field.Element{}, errors.New("leanvmclaims: circuit scratch too short")
	}
	scaledOne := alpha.Mul(column(c.ConstPos))
	var total field.Element
	for i, g := range c.Gates {
		if g[0] == 1 {
			scratch[i] = scratch[g[1]].Add(scratch[g[2]])
			continue
		}
		slot := g[1]
		if g[0] == 2 {
			slot = g[3]
		} else if g[0] == 3 {
			slot = g[2]
		}
		value := column(int(slot))
		left, right := value, scaledOne
		if g[0] == 2 {
			left = scratch[g[1]]
			right = alpha.Mul(scratch[g[2]])
		} else if g[0] == 3 {
			left = scratch[g[1]]
		}
		scratch[i] = value
		total = total.Add(row(int(slot)).Mul(left.Add(right)))
	}
	return total, nil
}

// BilinearCoefficients returns A and B such that Bilinear(alpha) = A + alpha*B.
// Gate scratch depends only on column weights, so both sums share one traversal.
func (c *Circuit) BilinearCoefficients(row, column func(int) field.Element, scratch []field.Element) (a, b field.Element, err error) {
	if len(scratch) < len(c.Gates) {
		return a, b, errors.New("leanvmclaims: circuit scratch too short")
	}
	constant := column(c.ConstPos)
	for i, g := range c.Gates {
		if g[0] == 1 {
			scratch[i] = scratch[g[1]].Add(scratch[g[2]])
			continue
		}
		slot := g[1]
		if g[0] == 2 {
			slot = g[3]
		} else if g[0] == 3 {
			slot = g[2]
		}
		value := column(int(slot))
		left, right := value, constant
		if g[0] == 2 {
			left, right = scratch[g[1]], scratch[g[2]]
		} else if g[0] == 3 {
			left = scratch[g[1]]
		}
		scratch[i] = value
		weight := row(int(slot))
		a = a.Add(weight.Mul(left))
		b = b.Add(weight.Mul(right))
	}
	return
}
