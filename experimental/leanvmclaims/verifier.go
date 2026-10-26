package leanvmclaims

import (
	"errors"
	"fmt"

	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/classkey"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/recursion"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/settlement"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/wire"
)

// UpstreamCommit is the exact supported mixed-tree protocol revision.
const UpstreamCommit = classkey.Pin

var ErrClass = errors.New("leanvmclaims: invalid class key or configuration")
var ErrProof = errors.New("leanvmclaims: invalid sealed proof")

// ClassVerifier holds authenticated, immutable class data. Construct it once and
// reuse it; simultaneous VerifySealed calls are supported. Its zero value rejects.
type ClassVerifier struct{ class *classkey.Validated }

// NewClassVerifier authenticates a canonical LVMXCK04 compact class key against an
// independently trusted digest, then derives its ordered leaf classes and tree
// configuration. The digest is BLAKE2s-256("leanvm/mixed-class-key/v4" || key).
// The constructor owns a copy; later caller mutations do not affect verification.
// Mirrors rec/tree/embed.rs::mixed_classes_from_bytes.
func NewClassVerifier(classKey []byte, expectedDigest [32]byte) (*ClassVerifier, error) {
	k, err := classkey.Load(classKey, expectedDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrClass, err)
	}
	return &ClassVerifier{class: k}, nil
}

// VerifySealed verifies a version-22 mixed root, canonical claim set and v3 seal.
// Root and seal use the pinned upstream binary encodings. It verifies the complete
// recursion proof, every carried matrix claim and each fixed-polynomial opening.
// It does not verify leaf proofs or support same-program trees. Input slices must
// remain unchanged until the call returns.
func (v *ClassVerifier) VerifySealed(claims ClaimSet, root, seal []byte) error {
	if v == nil || v.class == nil {
		return ErrClass
	}
	if err := v.verify(root, claims, seal); err != nil {
		return fmt.Errorf("%w: %w", ErrProof, err)
	}
	return nil
}
func (v *ClassVerifier) verify(rootBytes []byte, claims ClaimSet, sealBytes []byte) error {
	if err := claims.Check(v.class.Config.Claims, v.class.Config.Groups); err != nil {
		return err
	}
	root, err := wire.DecodeRootBounded(rootBytes, v.class.StatementWords)
	if err != nil {
		return err
	}
	seal, err := transcript.Decode(sealBytes)
	if err != nil {
		return err
	}
	// Cheap statement mismatches may reject before expensive proof arithmetic;
	// acceptance still requires every upstream verification obligation below.
	if err = settlement.Claims(v.class, root, claims); err != nil {
		return err
	}
	sealVerifier, values, err := settlement.BeginSeal(v.class, root, seal)
	if err != nil {
		return err
	}
	own, err := recursion.Verify(v.class, root, values)
	if err != nil {
		return err
	}
	if err = settlement.Matrices(v.class, root); err != nil {
		return err
	}
	return settlement.Seal(v.class, root, sealVerifier, own)
}

// ClassConfig describes the leaf classes and capacities authenticated by the key.
type ClassConfig = classkey.Config

// LeafClass describes one supported program class and its leaf-proof bounds.
type LeafClass = classkey.LeafClass

// LeafKind identifies the leaf verifier encoded in the authenticated class.
type LeafKind = classkey.LeafKind

const (
	PlainLeaf         LeafKind = classkey.Plain
	ZeroKnowledgeLeaf LeafKind = classkey.ZeroKnowledge
)

// SmallTier describes the optional lower-capacity recursion tier.
type SmallTier = classkey.SmallTier

// Config returns an independent snapshot of the authenticated class configuration.
// A nil or uninitialized verifier returns the zero configuration.
func (v *ClassVerifier) Config() ClassConfig {
	if v == nil || v.class == nil {
		return ClassConfig{}
	}
	c := v.class.Config
	c.Leaves = append([]LeafClass(nil), c.Leaves...)
	if c.Small != nil {
		small := *c.Small
		c.Small = &small
	}
	return c
}

// SetScratchCacheLimit is retained for source compatibility.
// Deprecated: compact-key verification no longer retains fixed-column scratch.
func SetScratchCacheLimit(bytes int) error {
	if bytes < 0 {
		return errors.New("leanvmclaims: negative scratch cache limit")
	}
	return nil
}
