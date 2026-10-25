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

const Pin = "da5c964831c993b011464e4fd4a573b7172d5295"
const Domain = "leanvm/mixed-class-key/v1"

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
	Digest      [32]byte
	Roots       [][32]byte
	Placeholder [32]byte
	Heights     [][6]uint64
	Circuits    []Circuit
	data        []byte
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

// Decode checks the trusted pin, the caller's expected descriptor and the wire
// structure. expectedDescriptor is the canonical Rust descriptor, excluding magic
// and including seal rate. It is not a self-authenticating trust root.
// No columns are expanded; one owned byte copy prevents later caller mutation.
func Decode(data []byte, pin [32]byte, expectedDescriptor []byte) (*Key, error) {
	data = bytes.Clone(data)
	if Digest(data) != pin {
		return nil, ErrDigest
	}
	r := reader{data: data}
	if !bytes.Equal(r.take(8), []byte("LVMXCK01")) {
		return nil, ErrEncoding
	}
	// 4 program dimensions, 11 leaf heights, then 7 tree-shape words.
	start := r.pos
	var descriptor [22]uint64
	for i := range descriptor {
		descriptor[i] = r.word()
	}
	small := descriptor[21]
	if small > 1 {
		return nil, ErrEncoding
	}
	arity := descriptor[17]
	if descriptor[16] == 0 || arity < 2 {
		return nil, ErrEncoding
	}
	if small == 1 {
		arity = r.word()
		claims, groups := r.word(), r.word()
		if arity < 2 || arity > descriptor[17] || claims > descriptor[19] || groups > descriptor[20] {
			return nil, ErrEncoding
		}
	}
	if r.word() != 2 {
		return nil, ErrEncoding
	}
	desc := data[start:r.pos]
	if !bytes.Equal(desc, expectedDescriptor) {
		return nil, ErrEncoding
	}
	tiers := 1 + small
	if r.word() != tiers {
		return nil, ErrEncoding
	}
	k := &Key{Digest: pin, Roots: make([][32]byte, int(tiers)), Heights: make([][6]uint64, int(tiers))}
	for i := range k.Roots {
		copy(k.Roots[i][:], r.take(32))
	}
	copy(k.Placeholder[:], r.take(32))
	if r.word() != tiers {
		return nil, ErrEncoding
	}
	for i := range k.Heights {
		k.Heights[i] = r.heights()
	}
	n := r.word()
	expectedCircuits := arity
	if small == 1 {
		if arity > ^uint64(0)-2 {
			return nil, ErrEncoding
		}
		expectedCircuits = arity + 2
	}
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
