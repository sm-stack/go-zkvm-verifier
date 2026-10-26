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

// LeafKind selects the upstream leaf verifier embedded in the class circuits.
type LeafKind uint64

const (
	Plain LeafKind = iota
	ZeroKnowledge
)

// LeafClass mirrors rec/tree/mixed.rs::LeafClass and ProgramClass.
type LeafClass struct {
	LogBytecode, LogRAM, LogAdvice, ImageWords, MaxMembers uint64
	LeafHeights                                            [11]uint64
	LeafRate                                               uint64
	Kind                                                   LeafKind
}

// ZKPlacement selects whether ZK First circuits share the base tier.
type ZKPlacement uint64

const (
	Shared ZKPlacement = iota
	Isolated
)

// Config is derived from the authenticated class-key descriptor.
type Config struct {
	Placement                               ZKPlacement
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
	if c.Placement > Isolated || len(c.Leaves) == 0 || c.TreeRate < 1 || c.TreeRate > 4 || c.Arity0 == 0 || c.Arity < 2 {
		return ErrClass
	}
	for _, leaf := range c.Leaves {
		if leaf.Kind > ZeroKnowledge || leaf.LeafRate < 1 || leaf.LeafRate > 4 || leaf.MaxMembers == 0 {
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
	DenseVars                                   []int
	Places                                      []Place
	DensePointVars, Polynomials, StatementWords int
	TierShift                                   int
	Codes                                       []uint64
	ProgramDigest, RootSession, SealSession     [32]byte
}

// Load mirrors embed.rs::mixed_classes_from_bytes_with and Design::new_with_zk,
// deriving the expected configuration from the authenticated key.
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
	v.Places = config.places()
	starts := make([]int, len(v.Layouts))
	counts := make([]int, len(v.Layouts))
	for i, p := range v.Places {
		if counts[p.Tier] == 0 {
			starts[p.Tier] = i
		}
		counts[p.Tier]++
	}
	v.DenseVars = make([]int, 2+max(2, len(v.Layouts)))
	v.DenseVars[0], v.DenseVars[1] = int(first.LogBytecode)+s.TupleBits, bits.Len64(first.ImageWords-1)
	for tier, l := range v.Layouts {
		kindBits := bits.Len(uint(counts[tier] - 1))
		v.TierShift = max(v.TierShift, kindBits)
		v.DenseVars[2+tier] = l.FixedVars + kindBits
	}
	for _, n := range v.DenseVars {
		v.DensePointVars = max(v.DensePointVars, n)
	}
	v.StatementWords = 3 + v.DensePointVars + v.Polynomials + len(v.Layouts) + 2*s.MaxKLog + 2*len(s.Circuits)
	v.Codes = make([]uint64, count)
	for i, c := range k.Circuits {
		if c.StatementWords != uint64(v.StatementWords) {
			return nil, ErrClass
		}
		place := v.Places[i]
		slot := (uint64(place.Tier) << uint(v.TierShift)) | uint64(i-starts[place.Tier])
		v.Codes[i] = slot << 1
		if !place.First {
			v.Codes[i] |= 1
		}
	}
	v.ProgramDigest = placeholderDigest(k.Placeholders[0], first)
	tag := append([]byte("leanvm-tree-19"), v.ProgramDigest[:]...)
	tag = append(tag, []byte("/mixed-members/2")...)
	if config.zkCount() > 0 {
		tag = append(tag, []byte("/zk-leaves/1")...)
		tag = append(tag, byte(config.Placement))
		for _, leaf := range config.Leaves {
			tag = append(tag, byte(leaf.Kind))
		}
	}
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
	v.SealSession = transcript.Session([]byte("leanvm/mixed-tree-seal/v3"), pin[:])
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

// Place maps the serialized circuit order to its tier and First/Node marker.
// Wrap and LeafWrap both use the Node marker and require fixed-claim settlement.
type Place struct {
	Tier  int
	First bool
}

func (c Config) zkCount() int {
	n := 0
	for _, l := range c.Leaves {
		if l.Kind == ZeroKnowledge {
			n++
		}
	}
	return n
}

// places mirrors Design::new_with_zk. Call only after circuit count is bounded
// by the encoded input, so an authenticated but oversized arity cannot allocate.
func (c Config) places() []Place {
	var out []Place
	zk := c.isolatedZKCount()
	for _, l := range c.Leaves {
		if l.Kind == Plain || c.Placement == Shared {
			out = append(out, Place{0, true})
		}
	}
	arity := c.Arity
	base := 1
	if c.Small != nil {
		arity = c.Small.Arity
		base = 2
	}
	for a := uint64(2); a <= arity; a++ {
		out = append(out, Place{0, false})
	}
	if c.Small != nil {
		out = append(out, Place{0, false})
	}
	for i := 0; i < zk; i++ {
		out = append(out, Place{0, false})
	}
	if c.Small != nil {
		out = append(out, Place{1, false})
	}
	for i := 0; i < zk; i++ {
		out = append(out, Place{base + i, true})
	}
	return out
}

func (c Config) isolatedZKCount() int {
	if c.Placement == Isolated {
		return c.zkCount()
	}
	return 0
}
