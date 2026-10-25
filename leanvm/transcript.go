package leanvm

import (
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/blake2s"
)

// Fiat-Shamir domain-separation tags: an absorbed block carries its tag in its last word.
const (
	dsObserve  = 1
	dsSqueeze  = 2
	dsPowBase  = 3
	dsPowNonce = 4
)

// queryGrindingBits is the proof of work before every WHIR level's queries.
const queryGrindingBits = 17

var (
	errStreamExhausted = errors.New("leanvm: proof stream exhausted")
	errBadGrind        = errors.New("leanvm: invalid grinding nonce")
	errNotConsumed     = errors.New("leanvm: proof not fully consumed")
	errBadMerkle       = errors.New("leanvm: invalid Merkle opening")
)

// digestWords returns a 32-byte digest's four little-endian words.
func digestWords(d [32]byte) [4]uint64 {
	var w [4]uint64
	for i := range w {
		w[i] = binary.LittleEndian.Uint64(d[8*i:])
	}
	return w
}

// compress is BLAKE2s of two four-word operands laid out little-endian into 64 bytes: the
// transcript's one primitive.
func compress(a, b [4]uint64) [4]uint64 {
	var in [64]byte
	for i := range 4 {
		binary.LittleEndian.PutUint64(in[8*i:], a[i])
		binary.LittleEndian.PutUint64(in[32+8*i:], b[i])
	}
	return digestWords(blake2s.Sum256(in[:]))
}

// transcript replays the prover's Fiat-Shamir transcript over a proof: scalars come off its stream
// and are bound as they are read, challenges are squeezed from the state, and Merkle openings come
// off its phases.
type transcript struct {
	state  [4]uint64
	proof  *wireProof
	offset int
	phase  int
}

// newTranscript seeds the state with the statement: the program digest and the output.
func newTranscript(proof *wireProof, iv [32]byte, publicInput [4]uint64) *transcript {
	return &transcript{state: compress(digestWords(iv), publicInput), proof: proof}
}

func (t *transcript) observe(v ext) {
	t.state = compress(t.state, [4]uint64{v.c0, v.c1, v.c2, dsObserve})
}

func (t *transcript) sample() ext {
	t.state = compress(t.state, [4]uint64{0, 0, 0, dsSqueeze})
	return ext{t.state[0], t.state[1], t.state[2]}
}

func (t *transcript) samples(n int) []ext {
	out := make([]ext, n)
	for i := range out {
		out[i] = t.sample()
	}
	return out
}

// takeRaw reads the next scalar without binding it.
func (t *transcript) takeRaw() (ext, error) {
	if t.offset >= len(t.proof.stream) {
		return ext{}, errStreamExhausted
	}
	v := t.proof.stream[t.offset]
	t.offset++
	return v, nil
}

func (t *transcript) nextScalar() (ext, error) {
	v, err := t.takeRaw()
	if err != nil {
		return ext{}, err
	}
	t.observe(v)
	return v, nil
}

func (t *transcript) nextScalars(n int) ([]ext, error) {
	out := make([]ext, n)
	for i := range out {
		v, err := t.nextScalar()
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}

// nextRoot reads a digest as its two 128-bit halves; a half with a nonzero top limb is no digest.
func (t *transcript) nextRoot() ([32]byte, error) {
	halves, err := t.nextScalars(2)
	if err != nil {
		return [32]byte{}, err
	}
	var root [32]byte
	for i, h := range halves {
		if h.c2 != 0 {
			return [32]byte{}, errors.New("leanvm: a digest half is 128-bit")
		}
		binary.LittleEndian.PutUint64(root[16*i:], h.c0)
		binary.LittleEndian.PutUint64(root[16*i+8:], h.c1)
	}
	return root, nil
}

// roundPoly reads a sumcheck round polynomial of count coefficients, constant first. The claim
// fixes the one coefficient that is not sent: c1 for a plain round (q(0) + q(1) = claim), c0 for a
// round whose eq factor r was factored out (c0 + r (c1 + ...) = claim).
func (t *transcript) roundPoly(count int, claim ext, eqFactor *ext) ([]ext, error) {
	coeffs := make([]ext, count)
	if eqFactor == nil {
		c0, err := t.nextScalar()
		if err != nil {
			return nil, err
		}
		tail, err := t.nextScalars(count - 2)
		if err != nil {
			return nil, err
		}
		coeffs[0], coeffs[1] = c0, claim.add(sumExt(tail))
		copy(coeffs[2:], tail)
		return coeffs, nil
	}
	tail, err := t.nextScalars(count - 1)
	if err != nil {
		return nil, err
	}
	coeffs[0] = claim.add(eqFactor.mul(sumExt(tail)))
	copy(coeffs[1:], tail)
	return coeffs, nil
}

// grindCheck reads the proof-of-work nonce, checks it, and binds it.
func (t *transcript) grindCheck(bits uint) error {
	nonce, err := t.takeRaw()
	if err != nil {
		return err
	}
	block := [4]uint64{nonce.c0, nonce.c1, nonce.c2, dsPowNonce}
	digest := compress(compress(t.state, [4]uint64{0, 0, 0, dsPowBase}), block)[0]
	valid := digest&(uint64(1)<<bits-1) == 0
	if bits == 0 {
		valid = nonce.isZero()
	}
	t.state = compress(t.state, block)
	if !valid {
		return errBadGrind
	}
	return nil
}

// merkle authenticates the next opening phase against root and returns each query's leaf image,
// in query order.
func (t *transcript) merkle(root [32]byte, numLeaves int, queries []int, rowWords, leafWords int) ([][]uint64, error) {
	if t.phase >= len(t.proof.merkle) {
		return nil, errBadMerkle
	}
	paths := &t.proof.merkle[t.phase]
	t.phase++
	return paths.open(root, numLeaves, queries, rowWords, leafWords)
}

func (t *transcript) finish() error {
	if t.offset != len(t.proof.stream) || t.phase != len(t.proof.merkle) {
		return errNotConsumed
	}
	return nil
}

// sumcheck runs rounds of a sumcheck, one per entry of equalities (an eq factor, or nil for a plain
// round), and returns the challenges and the final claim.
func (t *transcript) sumcheck(claim ext, count int, equalities []*ext) ([]ext, ext, error) {
	point := make([]ext, 0, len(equalities))
	for _, eq := range equalities {
		msg, err := t.roundPoly(count, claim, eq)
		if err != nil {
			return nil, ext{}, err
		}
		c := t.sample()
		point = append(point, c)
		claim = polyEval(msg, c)
	}
	return point, claim, nil
}

// plainRounds is n plain sumcheck rounds.
func plainRounds(n int) []*ext {
	return make([]*ext, n)
}

// eqRounds is one round per coordinate of point, each with that coordinate as its eq factor.
func eqRounds(point []ext) []*ext {
	out := make([]*ext, len(point))
	for i := range point {
		out[i] = &point[i]
	}
	return out
}
