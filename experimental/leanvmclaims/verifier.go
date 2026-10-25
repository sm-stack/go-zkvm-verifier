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

// ClassConfig fixes the expected program dimensions, leaf heights, rates,
// arities and claim capacities. Obtain it independently of untrusted proof data.
type ClassConfig = classkey.Config

// SmallTier configures the optional small tier of a two-tier mixed tree.
type SmallTier = classkey.SmallTier

var ErrClass = errors.New("leanvmclaims: invalid class key or configuration")
var ErrProof = errors.New("leanvmclaims: invalid sealed proof")

// ClassVerifier holds authenticated, immutable class data. Construct it once and
// reuse it; simultaneous VerifySealed calls are supported. Its zero value rejects.
type ClassVerifier struct{ class *classkey.Validated }

// NewClassVerifier authenticates a canonical LVMXCK01 class key against an
// independently trusted digest and expected class. The expected digest is
// BLAKE2s-256("leanvm/mixed-class-key/v1" || classKey). A digest supplied alongside
// an untrusted key is not a trust anchor. The constructor owns a copy of the key
// and configuration; subsequent caller mutations do not affect verification.
func NewClassVerifier(classKey []byte, expectedDigest [32]byte, expectedClass ClassConfig) (*ClassVerifier, error) {
	k, err := classkey.Load(classKey, expectedDigest, expectedClass)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrClass, err)
	}
	return &ClassVerifier{class: k}, nil
}

// VerifySealed verifies a version-20 mixed root, canonical claim set and v2 seal.
// All inputs use the pinned upstream binary encodings. It verifies the complete
// recursion proof, every carried matrix claim and each fixed-polynomial opening.
// It does not verify leaf proofs or support same-program trees. Input slices must
// remain unchanged until the call returns.
func (v *ClassVerifier) VerifySealed(root, claims, seal []byte) error {
	if v == nil || v.class == nil {
		return ErrClass
	}
	if err := v.verify(root, claims, seal); err != nil {
		return fmt.Errorf("%w: %w", ErrProof, err)
	}
	return nil
}
func (v *ClassVerifier) verify(rootBytes, claimBytes, sealBytes []byte) error {
	root, err := wire.DecodeRoot(rootBytes)
	if err != nil {
		return err
	}
	claims, err := wire.DecodeClaims(claimBytes)
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
	if err = recursion.Verify(v.class, root); err != nil {
		return err
	}
	if err = settlement.Matrices(v.class, root); err != nil {
		return err
	}
	return settlement.Seal(v.class, root, seal)
}
