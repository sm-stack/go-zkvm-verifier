// Package classkey decodes authenticated class-key containers for the mixed port.
// Mirrors rec/tree/embed.rs: digest, descriptor framing and Words decoding at Pin.
// Decode checks the container; Load additionally validates the class design,
// recursion layout and circuit keys before constructing reusable verifier data.
package classkey

import (
	"bytes"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/blake2s"
)

const Pin = "59c25cccfd5742f8216f259f9dd4d80d9a5f66e5"
const Domain = "leanvm/mixed-class-key/v2"

var ErrDigest = errors.New("leanvmclaims: class-key digest mismatch")
var ErrEncoding = errors.New("leanvmclaims: malformed class-key encoding")

// Digest uses upstream's exact unkeyed, unframed BLAKE2s domain separation.
func Digest(data []byte) [32]byte {
	h, _ := blake2s.New256(nil)
	h.Write([]byte(Domain))
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

type Column struct{ Offset, Words int }
type Circuit struct {
	StatementWords uint64
	Heights        [6]uint64
	Columns        [102]Column
}
type Key struct {
	Digest       [32]byte
	Roots        [][32]byte
	Placeholders [][32]byte
	Config       Config
	Heights      [][6]uint64
	Circuits     []Circuit
	data         []byte
}

// Word returns a fixed-column word. Caller indices must be checked by the verifier.
func (k *Key) Word(circuit, column, row int) (uint64, error) {
	if circuit < 0 || circuit >= len(k.Circuits) || column < 0 || column >= 102 {
		return 0, ErrEncoding
	}
	c := k.Circuits[circuit].Columns[column]
	if row < 0 || row >= c.Words {
		return 0, ErrEncoding
	}
	return binary.LittleEndian.Uint64(k.data[c.Offset+8*row:]), nil
}

type reader struct {
	data []byte
	pos  int
	err  error
}

func (r *reader) take(n uint64) []byte {
	if r.err != nil || n > uint64(len(r.data)-r.pos) {
		r.err = ErrEncoding
		return nil
	}
	b := r.data[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return b
}
func (r *reader) word() uint64 {
	b := r.take(8)
	if len(b) != 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(b)
}
func (r *reader) heights() (h [6]uint64) {
	for i := range h {
		h[i] = r.word()
		if h[i] > 32 {
			r.err = ErrEncoding
		}
	}
	return
}

// Decode authenticates and parses rec/tree/embed.rs class-key v2. Descriptor
// values come from the authenticated encoding. No fixed columns are expanded.
func Decode(data []byte, pin [32]byte) (*Key, error) {
	data = bytes.Clone(data)
	if Digest(data) != pin {
		return nil, ErrDigest
	}
	r := reader{data: data}
	if !bytes.Equal(r.take(8), []byte("LVMXCK02")) {
		return nil, ErrEncoding
	}
	nLeaves := r.word()
	if r.err != nil || nLeaves == 0 || nLeaves > uint64(len(data)-r.pos)/136 {
		return nil, ErrEncoding
	}
	config := Config{Leaves: make([]LeafClass, int(nLeaves))}
	for i := range config.Leaves {
		c := &config.Leaves[i]
		c.LogBytecode, c.LogRAM, c.LogAdvice, c.ImageWords, c.MaxMembers = r.word(), r.word(), r.word(), r.word(), r.word()
		for j := range c.LeafHeights {
			c.LeafHeights[j] = r.word()
		}
		c.LeafRate = r.word()
	}
	config.Arity0, config.Arity, config.TreeRate, config.Claims, config.Groups = r.word(), r.word(), r.word(), r.word(), r.word()
	small := r.word()
	if small > 1 {
		return nil, ErrEncoding
	}
	if small == 1 {
		config.Small = &SmallTier{r.word(), r.word(), r.word()}
	}
	if r.word() != 2 || config.check() != nil {
		return nil, ErrEncoding
	}
	tiers := 1 + small
	if r.word() != tiers {
		return nil, ErrEncoding
	}
	k := &Key{Digest: pin, Config: config, Roots: make([][32]byte, int(tiers)), Heights: make([][6]uint64, int(tiers)), Placeholders: make([][32]byte, int(nLeaves))}
	for i := range k.Roots {
		copy(k.Roots[i][:], r.take(32))
	}
	for i := range k.Placeholders {
		copy(k.Placeholders[i][:], r.take(32))
	}
	if r.word() != tiers {
		return nil, ErrEncoding
	}
	for i := range k.Heights {
		k.Heights[i] = r.heights()
	}
	n := r.word()
	arity := config.Arity
	extra := uint64(0)
	if config.Small != nil {
		arity = config.Small.Arity
		extra = 2
	}
	// Count is N + arity - 1 for one tier, N + small arity + 1 for two.
	if arity-1 > ^uint64(0)-nLeaves-extra {
		return nil, ErrEncoding
	}
	expectedCircuits := nLeaves + arity - 1 + extra
	// Each circuit needs 8 statement bytes, 48 heights, 8 count, 102 lengths.
	if r.err != nil || n != expectedCircuits || n > uint64(len(data)-r.pos)/880 {
		return nil, ErrEncoding
	}
	k.Circuits = make([]Circuit, int(n))
	for i := range k.Circuits {
		c := &k.Circuits[i]
		c.StatementWords = r.word()
		c.Heights = r.heights()
		tier := 0
		if small == 1 && i == len(k.Circuits)-1 {
			tier = 1
		}
		if c.Heights != k.Heights[tier] || r.word() != 102 {
			return nil, ErrEncoding
		}
		for j := range c.Columns {
			table := 5
			switch {
			case j < 4:
				table = 0
			case j < 8:
				table = 1
			case j < 24:
				table = 2
			case j < 89:
				table = 3
			case j < 97:
				table = 4
			}
			words := r.word()
			if r.err != nil || words != uint64(1)<<c.Heights[table] || words > uint64(len(data)-r.pos)/8 {
				return nil, ErrEncoding
			}
			c.Columns[j] = Column{Offset: r.pos, Words: int(words)}
			r.take(words * 8)
		}
	}
	if r.err != nil || r.pos != len(data) {
		return nil, ErrEncoding
	}
	k.data = data
	return k, nil
}
