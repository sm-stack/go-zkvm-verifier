package testutil

import (
	"encoding/binary"
	"github.com/sm-stack/go-zkvm-verifier/internal/gf2"
)

// Messages builds field-element transcript payloads for targeted rejection tests.
// It is not a prover; round order and constraints remain explicit in each test.
type Messages []byte

func (m *Messages) Elements(values ...gf2.Element) {
	for _, v := range values {
		*m = binary.LittleEndian.AppendUint64(*m, v.C0)
		*m = binary.LittleEndian.AppendUint64(*m, v.C1)
		*m = binary.LittleEndian.AppendUint64(*m, v.C2)
	}
}
func (m *Messages) Zeros(count int) {
	for range count {
		m.Elements(gf2.Zero)
	}
}
