// Derived from leanVM crates/fiat_shamir/src/{proof,verifier,pow}.rs at
// 59c25cccfd5742f8216f259f9dd4d80d9a5f66e5 (MIT; see NOTICE).
package transcript

import (
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/blake2s"
	"math/bits"
)

var ErrPOW = errors.New("leanvmclaims: insufficient proof of work")
var ErrTrailing = errors.New("leanvmclaims: unread transcript bytes")
var ErrHint = errors.New("leanvmclaims: unauthenticated hint")

// Proof borrows immutable input bytes. Hints are framed but are not transcript
// messages: the protocol must authenticate each hint before using its contents.
type Proof struct{ Messages, Hints []byte }

func Decode(data []byte) (Proof, error) {
	if len(data) < 8 {
		return Proof{}, errors.New("leanvmclaims: missing transcript length")
	}
	n := binary.LittleEndian.Uint64(data[:8])
	data = data[8:]
	if n > uint64(len(data)) {
		return Proof{}, errors.New("leanvmclaims: truncated transcript messages")
	}
	p := Proof{data[:int(n)], data[int(n):]}
	for rest := p.Hints; len(rest) != 0; {
		_, tail, ok := takeHint(rest)
		if !ok {
			return Proof{}, errors.New("leanvmclaims: malformed transcript hints")
		}
		rest = tail
	}
	return p, nil
}

func takeHint(data []byte) (head, tail []byte, ok bool) {
	if len(data) < 4 {
		return nil, data, false
	}
	n := uint64(binary.LittleEndian.Uint32(data[:4]))
	if n > uint64(len(data)-4) {
		return nil, data, false
	}
	return data[4 : 4+int(n)], data[4+int(n):], true
}

type Verifier struct {
	sponge                  Duplex
	messages, hints         []byte
	messagesRead, hintsRead int
	err                     error
}

func NewVerifier(session [32]byte, instance []byte, proof Proof) (*Verifier, error) {
	if len(instance) == 0 {
		return nil, errors.New("leanvmclaims: empty transcript instance")
	}
	v := &Verifier{sponge: New(session), messages: proof.Messages, hints: proof.Hints}
	v.sponge.Absorb(instance)
	return v, nil
}
func (v *Verifier) fail(err error) error {
	if v.err == nil {
		v.err = err
	}
	return v.err
}
func (v *Verifier) Public(data []byte) { v.sponge.Absorb(data) }

// Read consumes a fixed-size message and absorbs exactly its wire encoding.
// Every bit pattern is canonical for the byte, u64 and binary-field messages.
func (v *Verifier) Read(n int) ([]byte, error) {
	if v.err != nil {
		return nil, v.err
	}
	if n < 0 || n > len(v.messages) {
		return nil, v.fail(fmt.Errorf("leanvmclaims: message %d is truncated", v.messagesRead))
	}
	data := v.messages[:n]
	v.sponge.Absorb(data)
	v.messages = v.messages[n:]
	v.messagesRead++
	return data, nil
}
func (v *Verifier) Hint() ([]byte, error) {
	if v.err != nil {
		return nil, v.err
	}
	head, tail, ok := takeHint(v.hints)
	if !ok {
		return nil, v.fail(fmt.Errorf("leanvmclaims: hint %d is truncated", v.hintsRead))
	}
	v.hints = tail
	v.hintsRead++
	return head, nil
}
func (v *Verifier) InvalidHint() error { return v.fail(ErrHint) }
func (v *Verifier) Draw(out []byte) error {
	if v.err != nil {
		return v.err
	}
	if err := v.sponge.Squeeze(out); err != nil {
		return v.fail(err)
	}
	return nil
}
func (v *Verifier) CheckPOW(difficulty uint32) error {
	if difficulty == 0 {
		return nil
	}
	if difficulty > 63 {
		return v.fail(errors.New("leanvmclaims: invalid proof-of-work difficulty"))
	}
	var block [64]byte
	if err := v.Draw(block[:32]); err != nil {
		return err
	}
	nonce, err := v.Read(8)
	if err != nil {
		return err
	}
	copy(block[32:40], nonce)
	copy(block[56:], "FS-POW-1")
	digest := blake2s.Sum256(block[:])
	if bits.LeadingZeros64(binary.LittleEndian.Uint64(digest[:8])) < int(difficulty) {
		return v.fail(ErrPOW)
	}
	return nil
}
func (v *Verifier) EOF() error {
	if v.err != nil {
		return v.err
	}
	if len(v.messages) != 0 || len(v.hints) != 0 {
		return fmt.Errorf("%w (%d messages, %d hints)", ErrTrailing, len(v.messages), len(v.hints))
	}
	return nil
}
