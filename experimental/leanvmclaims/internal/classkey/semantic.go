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

// LeafClass mirrors rec/tree/mixed.rs::LeafClass and ProgramClass.
type LeafClass struct {
	LogBytecode, LogRAM, LogAdvice, ImageWords, MaxMembers uint64
	LeafHeights                                            [11]uint64
	LeafRate                                               uint64
}

// Config is derived from the authenticated class-key descriptor.
type Config struct {
	Leaves                                  []LeafClass
	Arity0, Arity, TreeRate, Claims, Groups uint64
	Small                                   *SmallTier
}
type SmallTier struct{ Arity, Claims, Groups uint64 }

func appendWords(dst []byte, words ...uint64) []byte {
	for _, w := range words {
		dst = binary.LittleEndian.AppendUint64(dst, w)
	}
	return dst
}
func (c Config) check() error {
	if len(c.Leaves) == 0 || c.TreeRate < 1 || c.TreeRate > 4 || c.Arity0 == 0 || c.Arity < 2 {
		return ErrClass
	}
	for _, leaf := range c.Leaves {
		if leaf.LeafRate < 1 || leaf.LeafRate > 4 || leaf.MaxMembers == 0 {
			return ErrClass
		}
	}
	if s := c.Small; s != nil && (s.Arity < 2 || s.Arity > c.Arity || s.Claims > c.Claims || s.Groups > c.Groups) {
		return ErrClass
	}
	return nil
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

// Load mirrors embed.rs::mixed_classes_from_bytes and design.rs::Design::new.
func Load(data []byte, pin [32]byte) (*Validated, error) {
	k, err := Decode(data, pin)
	if err != nil {
		return nil, err
	}
	config := k.Config
	s, err := machine.Load()
	if err != nil {
		return nil, err
	}
	// Validate dimensions before shifting or hashing the zero placeholder image.
	for _, c := range config.Leaves {
		if c.LogBytecode < uint64(s.MinBytecode) || c.LogBytecode > uint64(s.MaxMu-s.TupleBits) || c.LogRAM > 27 || c.LogAdvice > 26 || c.ImageWords == 0 || c.ImageWords&(c.ImageWords-1) != 0 || c.ImageWords > uint64(1)<<c.LogRAM {
			return nil, ErrClass
		}
		if _, err = s.LeafSize(c.LogBytecode, c.LogRAM, c.LogAdvice, c.LeafHeights); err != nil {
			return nil, err
		}
	}
	first := config.Leaves[0]
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
	v.DenseVars = [4]int{int(first.LogBytecode) + s.TupleBits, bits.Len64(first.ImageWords - 1), v.Layouts[0].FixedVars + v.TierShift, 0}
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
		v.Codes[i] = uint64(i) << 1
		if i == smallCount {
			v.Codes[i] = uint64(1) << uint(v.TierShift+1)
		}
		if i >= len(config.Leaves) {
			v.Codes[i] |= 1
		}
	}
	v.ProgramDigest = placeholderDigest(k.Placeholders[0], first)
	tag := append([]byte("leanvm-tree-18"), v.ProgramDigest[:]...)
	tag = append(tag, []byte("/mixed-members/2")...)
	tag = appendWords(tag, first.MaxMembers, uint64(len(config.Leaves)-1))
	for i, leaf := range config.Leaves[1:] {
		digest := placeholderDigest(k.Placeholders[i+1], leaf)
		tag = append(tag, digest[:]...)
		tag = appendWords(tag, leaf.LeafHeights[:]...)
		tag = appendWords(tag, leaf.MaxMembers)
		tag = append(tag, byte(leaf.LeafRate))
	}
	tag = appendWords(tag, first.LeafHeights[:]...)
	tag = appendWords(tag, config.Arity0, config.Arity, uint64(v.StatementWords), 1, config.Claims, config.Groups)
	if config.Small != nil {
		tag = appendWords(tag, config.Small.Arity, config.Small.Claims, config.Small.Groups)
	}
	for _, h := range k.Heights {
		tag = appendWords(tag, h[:]...)
	}
	tag = append(tag, byte(first.LeafRate), byte(config.TreeRate))
	v.RootSession = transcript.Session(tag, nil)
	v.SealSession = transcript.Session([]byte("leanvm/mixed-tree-seal/v2"), pin[:])
	return v, nil
}

func placeholderDigest(root [32]byte, c LeafClass) [32]byte {
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
