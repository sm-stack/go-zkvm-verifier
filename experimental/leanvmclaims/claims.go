// Mirrors rec/tree/multiset.rs::ClaimSet. Statement mapping uses four LE words
// for each 32-byte digest, as op_leanvm_tree::claim_set does.
package leanvmclaims

import (
	"encoding/binary"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/wire"
	"math"
	"slices"
)

// ClaimSet groups strictly increasing members under strictly increasing labels.
// Ordering compares uint64 words lexicographically, not encoded bytes.
type ClaimSet = wire.Claims
type ClaimGroup = wire.Group

// Statement identifies an authorized program and one member it committed.
// PublicValuesDigest denotes the member, not the leaf's list commitment output.
type Statement struct{ VkeyHash, PublicValuesDigest [32]byte }

// ClaimsFromStatements converts an already canonical statement list. It rejects
// duplicates and disorder instead of sorting or discarding statements.
func ClaimsFromStatements(statements []Statement) (ClaimSet, error) {
	var claims ClaimSet
	for _, s := range statements {
		var label [6]uint64
		var member [4]uint64
		for i := range 4 {
			label[i] = binary.LittleEndian.Uint64(s.VkeyHash[8*i:])
			member[i] = binary.LittleEndian.Uint64(s.PublicValuesDigest[8*i:])
		}
		if len(claims) == 0 || claims[len(claims)-1].Label != label {
			if len(claims) > 0 && slices.Compare(claims[len(claims)-1].Label[:], label[:]) >= 0 {
				return nil, wire.ErrEncoding
			}
			claims = append(claims, ClaimGroup{Label: label})
		}
		g := &claims[len(claims)-1]
		if len(g.Members) > 0 && slices.Compare(g.Members[len(g.Members)-1][:], member[:]) >= 0 {
			return nil, wire.ErrEncoding
		}
		g.Members = append(g.Members, member)
	}
	return claims, nil
}

// DecodeClaims parses the upstream claim-set encoding under this class's bounds.
// It checks counts before allocating and refuses noncanonical sets.
func (v *ClassVerifier) DecodeClaims(data []byte) (ClaimSet, error) {
	if v == nil || v.class == nil {
		return nil, ErrClass
	}
	return wire.DecodeClaimsBounded(data, v.class.Config.Claims, v.class.Config.Groups)
}

// EncodeClaims serializes a canonical set in the upstream wire format.
func EncodeClaims(claims ClaimSet) ([]byte, error) {
	if err := claims.Check(math.MaxUint64, math.MaxUint32); err != nil {
		return nil, err
	}
	out := binary.LittleEndian.AppendUint32(nil, uint32(len(claims)))
	for _, g := range claims {
		if uint64(len(g.Members)) > math.MaxUint32 {
			return nil, wire.ErrEncoding
		}
		for _, w := range g.Label {
			out = binary.LittleEndian.AppendUint64(out, w)
		}
		out = binary.LittleEndian.AppendUint32(out, uint32(len(g.Members)))
		for _, member := range g.Members {
			for _, w := range member {
				out = binary.LittleEndian.AppendUint64(out, w)
			}
		}
	}
	return out, nil
}
