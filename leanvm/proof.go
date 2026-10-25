package leanvm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"

	"golang.org/x/crypto/blake2s"
)

// proofMagic and proofVersion head a proof's bytes (leanvm::Proof).
var proofMagic = []byte("LVMP")

const proofVersion = 1

var errMalformedProof = errors.New("leanvm: malformed proof")

// wireProof is a decoded proof: the scalar stream and one pruned Merkle opening per phase
// (fiat_shamir::transcript::Proof).
type wireProof struct {
	stream []ext
	merkle []prunedPaths
}

// prunedPaths is one opening phase: the rows at each distinct queried position, ascending, and one
// "octopus" of sibling digests authenticating all of them (fiat_shamir::merkle::PrunedMerklePaths).
type prunedPaths struct {
	leafData [][]uint64
	siblings [][32]byte
}

// decodeProof decodes a proof's bytes as leanvm::Proof::from_bytes does: the magic, the version,
// then the body in bincode's fixed-width little-endian encoding, with no trailing bytes.
func decodeProof(data []byte) (*wireProof, error) {
	if len(data) < 6 || !bytes.Equal(data[:4], proofMagic) {
		return nil, errMalformedProof
	}
	if binary.LittleEndian.Uint16(data[4:6]) != proofVersion {
		return nil, errors.New("leanvm: unsupported proof version")
	}
	r := &reader{data: data[6:]}
	p := &wireProof{}
	n, ok := r.length(24)
	if !ok {
		return nil, errMalformedProof
	}
	p.stream = make([]ext, n)
	for i := range p.stream {
		p.stream[i] = ext{r.u64(), r.u64(), r.u64()}
	}
	phases, ok := r.length(16)
	if !ok {
		return nil, errMalformedProof
	}
	p.merkle = make([]prunedPaths, phases)
	for i := range p.merkle {
		rows, ok := r.length(8)
		if !ok {
			return nil, errMalformedProof
		}
		leafData := make([][]uint64, rows)
		for j := range leafData {
			words, ok := r.length(8)
			if !ok {
				return nil, errMalformedProof
			}
			leafData[j] = make([]uint64, words)
			for k := range leafData[j] {
				leafData[j][k] = r.u64()
			}
		}
		siblings, ok := r.length(32)
		if !ok {
			return nil, errMalformedProof
		}
		p.merkle[i] = prunedPaths{leafData: leafData, siblings: make([][32]byte, siblings)}
		for j := range p.merkle[i].siblings {
			copy(p.merkle[i].siblings[j][:], r.take(32))
		}
	}
	if len(r.data) != 0 {
		return nil, errMalformedProof
	}
	return p, nil
}

// reader reads fixed-width fields after callers validate their byte ranges.
// length validates a whole sequence before its unchecked element reads.
type reader struct {
	data []byte
}

// length reads a sequence length and checks that the bytes left could hold that many elements of at
// least minSize bytes each. Bincode reads such a sequence until it runs out of bytes, so a length
// failing this check fails to decode either way.
func (r *reader) length(minSize int) (int, bool) {
	if len(r.data) < 8 {
		return 0, false
	}
	n := binary.LittleEndian.Uint64(r.data)
	r.data = r.data[8:]
	if n > uint64(len(r.data)/minSize) {
		return 0, false
	}
	return int(n), true
}

func (r *reader) u64() uint64 {
	v := binary.LittleEndian.Uint64(r.data)
	r.data = r.data[8:]
	return v
}

func (r *reader) take(n int) []byte {
	out := r.data[:n]
	r.data = r.data[n:]
	return out
}

// hashPair hashes two children into their parent.
func hashPair(left, right [32]byte) [32]byte {
	var buf [64]byte
	copy(buf[:32], left[:])
	copy(buf[32:], right[:])
	return blake2s.Sum256(buf[:])
}

// hashLeaf hashes a leaf image: its words, little-endian.
func hashLeaf(image []uint64) [32]byte {
	buf := make([]byte, 8*len(image))
	for i, w := range image {
		binary.LittleEndian.PutUint64(buf[8*i:], w)
	}
	return blake2s.Sum256(buf)
}

// leafImage restores a stored row's omitted zero prefix.
func leafImage(row []uint64, leafWords int) []uint64 {
	image := make([]uint64, leafWords)
	copy(image[leafWords-len(row):], row)
	return image
}

type node struct {
	index int
	hash  [32]byte
}

// open authenticates the phase against root and expands it into one leaf image per query, in query
// order, as PrunedMerklePaths::open does: every row rowWords wide, one row per distinct query, every
// query inside the tree, and exactly the siblings the octopus needs.
func (p *prunedPaths) open(root [32]byte, numLeaves int, queries []int, rowWords, leafWords int) ([][]uint64, error) {
	if numLeaves <= 0 || numLeaves&(numLeaves-1) != 0 || len(queries) == 0 {
		return nil, errBadMerkle
	}
	height := bitLen(uint64(numLeaves)) - 1
	sorted := slices.Clone(queries)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	if len(sorted) != len(p.leafData) || rowWords > leafWords {
		return nil, errBadMerkle
	}
	nodes := make([]node, len(sorted))
	for i, row := range p.leafData {
		if len(row) != rowWords {
			return nil, errBadMerkle
		}
		nodes[i] = node{sorted[i], hashLeaf(leafImage(row, leafWords))}
	}
	if sorted[len(sorted)-1] >= numLeaves || sorted[0] < 0 {
		return nil, errBadMerkle
	}

	supplied := p.siblings
	for range height {
		parents := make([]node, 0, len(nodes))
		for i := 0; i < len(nodes); {
			idx := nodes[i].index
			paired := idx&1 == 0 && i+1 < len(nodes) && nodes[i+1].index == idx|1
			var left, right [32]byte
			switch {
			case paired:
				left, right = nodes[i].hash, nodes[i+1].hash
			case len(supplied) == 0:
				return nil, errBadMerkle
			case idx&1 == 0:
				left, right = nodes[i].hash, supplied[0]
				supplied = supplied[1:]
			default:
				left, right = supplied[0], nodes[i].hash
				supplied = supplied[1:]
			}
			parents = append(parents, node{idx >> 1, hashPair(left, right)})
			if paired {
				i += 2
			} else {
				i++
			}
		}
		nodes = parents
	}
	if len(supplied) != 0 || nodes[0].hash != root {
		return nil, errBadMerkle
	}

	out := make([][]uint64, len(queries))
	for i, q := range queries {
		slot, _ := slices.BinarySearch(sorted, q)
		out[i] = leafImage(p.leafData[slot], leafWords)
	}
	return out, nil
}
