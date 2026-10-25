// CREDIT: https://github.com/succinctlabs/flock (flock-core), MIT OR Apache-2.0.
// Copyright (c) 2026 Bain Capital Crypto, LP and Ron Rothblum
// Modifications copyright 2026 Succinct Labs, Benedikt Bunz, William Wang
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Port of leanVM pcs/src/{merkle,verifier}.rs at da5c964831c993b011464e4fd4a573b7172d5295.
package pcs

import (
	"encoding/binary"
	"errors"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
	"golang.org/x/crypto/blake2s"
	"slices"
)

var ErrOpening = errors.New("leanvmclaims: malformed or unauthenticated Merkle opening")

type merkleNode struct {
	index uint64
	hash  [32]byte
}

// OpenRows authenticates the pruned paths before releasing rows, in query order.
// Dimensions come from the validated commitment configuration, not the hint.
func OpenRows(root [32]byte, depth int, queries []uint64, rowWords, leafWords int, hint []byte) ([][]uint64, error) {
	if depth < 0 || depth > 63 || len(queries) == 0 || rowWords <= 0 || leafWords < rowWords {
		return nil, ErrOpening
	}
	sorted := slices.Clone(queries)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	if sorted[len(sorted)-1] >= uint64(1)<<uint(depth) {
		return nil, ErrOpening
	}
	if rowWords > len(hint)/8/len(sorted) {
		return nil, ErrOpening
	}
	rowBytes := rowWords * 8
	rows := hint[:len(sorted)*rowBytes]
	siblings := hint[len(sorted)*rowBytes:]
	if len(siblings)%32 != 0 {
		return nil, ErrOpening
	}
	nodes := make([]merkleNode, len(sorted))
	// Stream the zero prefix instead of allocating a potentially large padded image.
	var zeros [256]byte
	for i, q := range sorted {
		h, _ := blake2s.New256(nil)
		for words := leafWords - rowWords; words > 0; {
			n := min(words, len(zeros)/8)
			_, _ = h.Write(zeros[:n*8])
			words -= n
		}
		_, _ = h.Write(rows[i*rowBytes : (i+1)*rowBytes])
		nodes[i].index = q
		copy(nodes[i].hash[:], h.Sum(nil))
	}
	for level := 0; level < depth; level++ {
		parents := make([]merkleNode, 0, (len(nodes)+1)/2)
		for i := 0; i < len(nodes); {
			index := nodes[i].index
			paired := index&1 == 0 && i+1 < len(nodes) && nodes[i+1].index == index|1
			var left, right [32]byte
			if paired {
				left = nodes[i].hash
				right = nodes[i+1].hash
				i += 2
			} else {
				if len(siblings) < 32 {
					return nil, ErrOpening
				}
				var sibling [32]byte
				copy(sibling[:], siblings[:32])
				siblings = siblings[32:]
				if index&1 == 0 {
					left = nodes[i].hash
					right = sibling
				} else {
					left = sibling
					right = nodes[i].hash
				}
				i++
			}
			var pair [64]byte
			copy(pair[:32], left[:])
			copy(pair[32:], right[:])
			parents = append(parents, merkleNode{index >> 1, blake2s.Sum256(pair[:])})
		}
		nodes = parents
	}
	if len(siblings) != 0 || len(nodes) != 1 || nodes[0].hash != root {
		return nil, ErrOpening
	}
	out := make([][]uint64, len(queries))
	for i, q := range queries {
		pos, _ := slices.BinarySearch(sorted, q)
		out[i] = make([]uint64, rowWords)
		for j := range out[i] {
			out[i][j] = binary.LittleEndian.Uint64(rows[pos*rowBytes+j*8:])
		}
	}
	return out, nil
}

func ReadRows(v *transcript.Verifier, root [32]byte, depth int, queries []uint64, rowWords, leafWords int) ([][]uint64, error) {
	hint, e := v.Hint()
	if e != nil {
		return nil, e
	}
	rows, e := OpenRows(root, depth, queries, rowWords, leafWords, hint)
	if e != nil {
		return nil, v.InvalidHint()
	}
	return rows, nil
}

// SampleQueries extracts disjoint low-first chunks of 192-bit challenges and
// replaces their top bits with the count's binary-stratification groups.
func SampleQueries(v *transcript.Verifier, depth, count int) ([]uint64, error) {
	if depth <= 0 || depth > 63 || count < 0 {
		return nil, ErrOpening
	}
	out := make([]uint64, 0, count)
	mask := uint64(1)<<uint(depth) - 1
	for len(out) < count {
		var data [24]byte
		if e := v.Draw(data[:]); e != nil {
			return nil, e
		}
		limbs := [3]uint64{binary.LittleEndian.Uint64(data[:8]), binary.LittleEndian.Uint64(data[8:16]), binary.LittleEndian.Uint64(data[16:])}
		n := min(192/depth, count-len(out))
		for j := 0; j < n; j++ {
			off := j * depth
			li, shift := off/64, off%64
			chunk := limbs[li] >> uint(shift)
			if shift+depth > 64 {
				chunk |= limbs[li+1] << uint(64-shift)
			}
			out = append(out, chunk&mask)
		}
	}
	at := 0
	for g := 62; g >= 0; g-- {
		if uint64(count)>>uint(g)&1 == 0 {
			continue
		}
		width := min(g, depth)
		low := depth - width
		lowMask := uint64(1)<<uint(low) - 1
		topMask := uint64(1)<<uint(width) - 1
		for j := uint64(0); j < uint64(1)<<uint(g); j++ {
			out[at] = (out[at] & lowMask) | (j&topMask)<<uint(low)
			at++
		}
	}
	return out, nil
}
