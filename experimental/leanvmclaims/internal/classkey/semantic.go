package classkey

import (
	"encoding/binary"
	"errors"
	"math/bits"

	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/machine"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
	"golang.org/x/crypto/blake2s"
)

var ErrClass = errors.New("leanvmclaims: invalid class or inconsistent verifier data")

// Config is the expected relation, supplied independently of the class key.
// All sizes are protocol integers, not host-sized allocation requests.
type Config struct {
	LogBytecode, LogRAM, LogAdvice, ImageWords uint64
	LeafHeights                                [11]uint64
	LeafRate, Arity0, Arity, TreeRate          uint64
	Claims, Groups                             uint64
	Small                                      *SmallTier
}
type SmallTier struct{ Arity, Claims, Groups uint64 }

func appendWords(dst []byte, words ...uint64) []byte {
	for _, w := range words {
		dst = binary.LittleEndian.AppendUint64(dst, w)
	}
	return dst
}
func (c Config) Descriptor() ([]byte, error) {
	if c.LeafRate < 1 || c.LeafRate > 4 || c.TreeRate < 1 || c.TreeRate > 4 || c.Arity0 == 0 || c.Arity < 2 {
		return nil, ErrClass
	}
	out := appendWords(nil, c.LogBytecode, c.LogRAM, c.LogAdvice, c.ImageWords)
	out = appendWords(out, c.LeafHeights[:]...)
	out = appendWords(out, c.LeafRate, c.Arity0, c.Arity, c.TreeRate, c.Claims, c.Groups)
	if c.Small == nil {
		out = appendWords(out, 0)
	} else {
		s := c.Small
		if s.Arity < 2 || s.Arity > c.Arity || s.Claims > c.Claims || s.Groups > c.Groups {
			return nil, ErrClass
		}
		out = appendWords(out, 1, s.Arity, s.Claims, s.Groups)
	}
	return appendWords(out, 2), nil
}

// Validated holds the layout and sessions derived from an authenticated key.
// This is constructor validation, not a proof verification result.
type Validated struct {
	Key                                         *Key
	Config                                      Config
	Layouts                                     []*machine.Layout
	DenseVars                                   [4]int
	DensePointVars, Polynomials, StatementWords int
	TierShift                                   int
	Codes                                       []uint64
	ProgramDigest, RootSession, SealSession     [32]byte
}

func Load(data []byte, pin [32]byte, config Config) (*Validated, error) {
	desc, err := config.Descriptor()
	if err != nil {
		return nil, err
	}
	s, err := machine.Load()
	if err != nil {
		return nil, err
	}
	// RiscvProgram::padded and mixed_placeholder_with_root. Validate before
	// shifting or streaming the zero image; do not allocate dummy program tables.
	if config.LogBytecode < uint64(s.MinBytecode) || config.LogBytecode > uint64(s.MaxMu-s.TupleBits) || config.LogRAM > 27 || config.LogAdvice > 26 || config.ImageWords == 0 || config.ImageWords&(config.ImageWords-1) != 0 || config.ImageWords > uint64(1)<<config.LogRAM {
		return nil, ErrClass
	}
	_, err = s.LeafSize(config.LogBytecode, config.LogRAM, config.LogAdvice, config.LeafHeights)
	if err != nil {
		return nil, err
	}
	k, err := Decode(data, pin, desc)
	if err != nil {
		return nil, err
	}
	if config.Small != nil {
		small := *config.Small
		config.Small = &small
	}
	v := &Validated{Key: k, Config: config, Polynomials: 2 + len(k.Heights)}
	for _, h := range k.Heights {
		l, err := machine.NewLayout(h)
		if err != nil {
			return nil, err
		}
		v.Layouts = append(v.Layouts, l)
	}
	// Decode has already bounded the circuit count by the actual encoded bytes.
	count := len(k.Circuits)
	smallCount := count
	if len(v.Layouts) == 2 {
		smallCount--
	}
	v.TierShift = bits.Len(uint(smallCount - 1))
	v.DenseVars = [4]int{int(config.LogBytecode) + s.TupleBits, bits.Len64(config.ImageWords - 1), v.Layouts[0].FixedVars + v.TierShift, 0}
	if len(v.Layouts) == 2 {
		v.DenseVars[3] = v.Layouts[1].FixedVars
	}
	for _, n := range v.DenseVars {
		v.DensePointVars = max(v.DensePointVars, n)
	}
	v.StatementWords = 3 + v.DensePointVars + v.Polynomials + 2*s.MaxKLog + 2*len(s.Circuits)
	v.Codes = make([]uint64, count)
	for i, c := range k.Circuits {
		if c.StatementWords != uint64(v.StatementWords) {
			return nil, ErrClass
		}
		v.Codes[i] = uint64(i)
		if i == smallCount {
			v.Codes[i] = uint64(1) << uint(v.TierShift)
		}
	}
	v.ProgramDigest = placeholderDigest(k.Placeholder, config)
	tag := append([]byte("leanvm-tree-17"), v.ProgramDigest[:]...)
	tag = append(tag, []byte("/mixed-program/1")...)
	tag = appendWords(tag, config.LeafHeights[:]...)
	tag = appendWords(tag, config.Arity0, config.Arity, uint64(v.StatementWords), 1, config.Claims, config.Groups)
	if config.Small != nil {
		tag = appendWords(tag, config.Small.Arity, config.Small.Claims, config.Small.Groups)
	}
	for _, h := range k.Heights {
		tag = appendWords(tag, h[:]...)
	}
	tag = append(tag, byte(config.LeafRate), byte(config.TreeRate))
	v.RootSession = transcript.Session(tag, nil)
	v.SealSession = transcript.Session([]byte("leanvm/mixed-tree-seal/v2"), pin[:])
	return v, nil
}

func placeholderDigest(root [32]byte, c Config) [32]byte {
	h, _ := blake2s.New256(nil)
	h.Write([]byte("leanvm-rv64im-committed-1"))
	h.Write(root[:])
	h.Write(appendWords(nil, c.LogBytecode, 0x10000000, c.LogRAM, c.LogAdvice, c.ImageWords))
	var zeros [8192]byte
	for remaining := c.ImageWords * 8; remaining > 0; {
		n := min(remaining, uint64(len(zeros)))
		h.Write(zeros[:n])
		remaining -= n
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
