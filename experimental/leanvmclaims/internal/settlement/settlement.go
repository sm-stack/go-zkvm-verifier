// Derived from pinned rec/tree/{mod,seal,statement}.rs. Upstream MIT: NOTICE.
// Package settlement checks claims carried by a root; it does NOT verify the
// root's recursion proof. The caller must complete that check independently.
package settlement

import (
	"encoding/binary"
	"errors"
	"slices"

	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/classkey"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/field"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/machine"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/pcs"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/wire"
)

type E = field.Element

var ErrStatement = errors.New("leanvmclaims: invalid root statement or unsettled claim")

func Position(k *classkey.Validated, root wire.Root) (int, error) {
	if len(root.Words) != k.StatementWords || uint64(root.Rate) != k.Config.TreeRate {
		return 0, ErrStatement
	}
	p := slices.Index(k.Codes, root.Circuit)
	if p < 0 {
		return 0, ErrStatement
	}
	return p, nil
}
func Claims(k *classkey.Validated, root wire.Root, claims wire.Claims) error {
	if _, err := Position(k, root); err != nil {
		return err
	}
	if err := claims.Check(k.Config.Claims, k.Config.Groups); err != nil {
		return err
	}
	digest := claims.Digest()
	for i, w := range [4]uint64{root.Words[1][0], root.Words[1][1], root.Words[2][0], root.Words[2][1]} {
		if w != binary.LittleEndian.Uint64(digest[i*8:]) {
			return ErrStatement
		}
	}
	return nil
}
func elements(words []wire.Element) []E {
	out := make([]E, len(words))
	for i, w := range words {
		out[i] = E{C0: w[0], C1: w[1], C2: w[2]}
	}
	return out
}

// Matrices checks every carried circuit matrix against the pinned gate lists.
func Matrices(k *classkey.Validated, root wire.Root) error {
	if _, err := Position(k, root); err != nil {
		return err
	}
	s, err := machine.Load()
	if err != nil {
		return err
	}
	start := 3 + k.DensePointVars + k.Polynomials + len(k.Layouts)
	rows := elements(root.Words[start : start+s.MaxKLog])
	start += s.MaxKLog
	cols := elements(root.Words[start : start+s.MaxKLog])
	start += s.MaxKLog
	values := elements(root.Words[start:])
	maxGates := 0
	for _, c := range s.Circuits {
		maxGates = max(maxGates, len(c.Gates))
	}
	scratch := make([]E, maxGates)
	for i, c := range s.Circuits {
		r, w := field.EqTable(rows[:c.KLog]), field.EqTable(cols[:c.KLog])
		row, col := func(i int) E { return r[i] }, func(i int) E { return w[i] }
		a, b, err := c.BilinearCoefficients(row, col, scratch)
		if err != nil {
			return err
		}
		if a != values[2*i] || b != values[2*i+1] {
			return ErrStatement
		}
	}
	return nil
}

// BeginSeal binds all supplied column values before any PCS challenges.
func BeginSeal(k *classkey.Validated, root wire.Root, proof transcript.Proof) (*transcript.Verifier, [102]E, error) {
	var values [102]E
	if _, err := Position(k, root); err != nil {
		return nil, values, err
	}
	v, err := transcript.NewVerifier(k.SealSession, root.SealInstance(), proof)
	if err != nil {
		return nil, values, err
	}
	count, err := v.Read(8)
	if err != nil {
		return nil, values, err
	}
	if binary.LittleEndian.Uint64(count) != 102 {
		return nil, values, ErrStatement
	}
	r := transcript.FieldReader{Verifier: v}
	for i := range values {
		values[i] = r.ReadElement()
	}
	return v, values, r.Err
}

// Seal authenticates the root's consumed columns and selectively opens carried
// fixed claims. The caller must first verify the root and carried matrix claims.
func Seal(k *classkey.Validated, root wire.Root, v *transcript.Verifier, own []pcs.PointClaim) error {
	position, err := Position(k, root)
	if err != nil {
		return err
	}
	if len(own) != 102 {
		return ErrStatement
	}
	dense := elements(root.Words[3 : 3+k.DensePointVars])
	values := elements(root.Words[3+k.DensePointVars : 3+k.DensePointVars+k.Polynomials])
	usageAt := 3 + k.DensePointVars + k.Polynomials
	for tier := range k.Layouts {
		used := root.Words[usageAt+tier]
		var claims []pcs.PointClaim
		if used == (wire.Element{1, 0, 0}) {
			claims = append(claims, pcs.PointClaim{Point: dense[:k.DenseVars[2+tier]], Value: values[2+tier]})
		} else if used != (wire.Element{}) || values[2+tier] != (E{}) {
			return ErrStatement
		}
		if tier == k.Places[position].Tier {
			claims = append(claims, own...)
		}
		if len(claims) == 0 {
			continue
		}
		vars := k.DenseVars[2+tier]
		logN := max(15, vars)
		if logN > 28 {
			return ErrStatement
		}
		length := uint64(1) << uint(vars)
		lane := uint64(1) << uint(logN-6)
		lanes := int((length + lane - 1) / lane)
		if err = pcs.VerifyStack(v, k.Key.Roots[tier], logN, 2, lanes, claims, nil); err != nil {
			return err
		}
	}
	return v.EOF()
}
