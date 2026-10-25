// Derived from the pinned fiat_shamir field-element encoding; see NOTICE.
package transcript

import (
	"encoding/binary"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/field"
)

// FieldReader reads or samples 24-byte extension elements, retaining the first error.
type FieldReader struct {
	Verifier *Verifier
	Err      error
}

func (r *FieldReader) Element(draw bool) field.Element {
	if r.Err != nil {
		return field.Element{}
	}
	var b []byte
	if draw {
		b = make([]byte, 24)
		r.Err = r.Verifier.Draw(b)
	} else {
		b, r.Err = r.Verifier.Read(24)
	}
	if r.Err != nil {
		return field.Element{}
	}
	return field.Element{C0: binary.LittleEndian.Uint64(b), C1: binary.LittleEndian.Uint64(b[8:]), C2: binary.LittleEndian.Uint64(b[16:])}
}
func (r *FieldReader) ReadElement() field.Element { return r.Element(false) }
func (r *FieldReader) DrawElement() field.Element { return r.Element(true) }
func (r *FieldReader) Elements(n int, draw bool) []field.Element {
	out := make([]field.Element, n)
	for i := range out {
		out[i] = r.Element(draw)
	}
	return out
}
