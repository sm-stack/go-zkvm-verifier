// Derived from leanVM crates/fiat_shamir/src/duplex.rs at
// fc3fc9ec0ec218d6b5196ecae85a975590729ae6 (MIT; see NOTICE).
package transcript

import (
	"encoding/binary"
	"errors"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/blake"
)

const maxSqueeze = uint64(1<<49) - 1

// Duplex implements the pinned BLAKE2s compression-based streaming sponge.
// It is a value type; copying it forks the transcript without shared state.
type Duplex struct {
	cv                 [8]uint32
	pending            [64]byte
	n                  int
	first              bool
	previous, squeezed uint64
	output             [32]byte
}

func New(iv [32]byte) Duplex {
	var block [64]byte
	copy(block[:], iv[:])
	cv := blake.ParameterIV()
	return Duplex{cv: node(cv, block, 1<<56), first: true}
}

func (d *Duplex) flush(last bool) {
	clear(d.pending[d.n:])
	role := uint64(3)
	if d.first {
		role = 2
	}
	if last {
		if d.first {
			role = 4
		} else {
			role = 5
		}
	}
	d.cv = node(d.cv, d.pending, role<<56|uint64(d.n)<<49|d.previous)
	d.n = 0
	d.first = last
	d.previous = 0
}

func (d *Duplex) Absorb(input []byte) {
	if len(input) == 0 {
		return
	}
	if d.squeezed != 0 {
		d.previous = d.squeezed
		d.squeezed = 0
	}
	for len(input) > 0 {
		if d.n == 64 {
			d.flush(false)
		}
		n := copy(d.pending[d.n:], input)
		d.n += n
		input = input[n:]
	}
}

// Squeeze refuses the protocol's framing-counter overflow before mutating state.
func (d *Duplex) Squeeze(out []byte) error {
	if len(out) == 0 {
		return nil
	}
	if uint64(len(out)) > maxSqueeze-d.squeezed {
		return errors.New("leanvmclaims: transcript squeeze overflow")
	}
	if d.n != 0 {
		d.flush(true)
	}
	for len(out) > 0 {
		offset := int(d.squeezed % 32)
		if offset == 0 {
			var block [64]byte
			binary.LittleEndian.PutUint64(block[:8], d.squeezed/32)
			words := node(d.cv, block, 6<<56)
			for i, w := range words {
				binary.LittleEndian.PutUint32(d.output[i*4:], w)
			}
		}
		n := copy(out, d.output[offset:])
		d.squeezed += uint64(n)
		out = out[n:]
	}
	return nil
}

// Session derives a session with the upstream Fiat–Shamir framing. It is not a
// plain hash of protocol || relation. Callers provide a fixed-length relation.
func Session(protocol, relation []byte) [32]byte {
	var iv [32]byte
	copy(iv[:], "irtf-cfrg-fiat-shamir/session-id")
	d := New(iv)
	d.Absorb(protocol)
	d.Absorb(relation)
	var out [32]byte
	_ = d.Squeeze(out[:]) // A fresh sponge always admits 32 output bytes.
	return out
}

func node(cv [8]uint32, block [64]byte, counter uint64) [8]uint32 {
	return blake.Compress(cv, block, counter, true)
}
