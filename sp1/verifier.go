// Package sp1 verifies SP1 6.8.1 compressed proofs; see UPSTREAM.md for pins and wire policy.
package sp1

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"lukechampine.com/blake3"
)

// The bounds op-sp1-proofs checks before verifying: the verifier absorbs every chip name byte into
// its transcript before it checks the names against the machine.
const (
	// maxChips bounds the chips an compressed proof opens. The compress machine has 8.
	maxChips = 32
	// maxChipNameBytes bounds a chip name in an compressed proof.
	maxChipNameBytes = 64
)

// Verify verifies proof, a bincode-encoded SP1Proof::Compressed, for the program whose verifying key
// digest is vkeyHash (eight big-endian 32-bit words) and whose committed public values are
// publicValues.
// Verification may use one auxiliary Merkle worker when GOMAXPROCS > 1.
// There is no per-call worker setting; GOMAXPROCS=1 uses the serial path.
func Verify(vkeyHash [32]byte, publicValues []byte, proof []byte) error {
	var vkey digest
	for i := range vkey {
		word := binary.BigEndian.Uint32(vkeyHash[4*i:])
		if word >= fieldOrder {
			return errors.New("program vkey hash is not a KoalaBear digest")
		}
		vkey[i] = felt(word)
	}
	p, err := decodeCompressedProof(proof)
	if err != nil {
		return err
	}
	if err := checkPublicValuesCommitment(p.shard.publicValues, publicValues); err != nil {
		return err
	}
	return verifyCompressed(p, vkey)
}

func checkPublicValuesCommitment(pv []felt, publicValues []byte) error {
	if len(pv) != numPublicValues {
		return errInvalidPublicValues
	}
	// The proven program committed to the hash of its public values: SHA-256 or BLAKE3, in full.
	committed := make([]byte, 32)
	for i := range committed {
		committed[i] = byte(pv[pvCommittedValueDigest+i])
	}
	sha := sha256.Sum256(publicValues)
	if bytes.Equal(committed, sha[:]) {
		return nil
	}
	b3 := blake3.Sum256(publicValues)
	if !bytes.Equal(committed, b3[:]) {
		return errors.New("given public values do not match the commitment in the proof")
	}
	return nil
}

// verifyCompressed checks the shard proof, that it is a complete proof of the program with digest
// vkey, and that it was made with one of SP1's recursion verifying keys.
func verifyCompressed(p *compressedProof, vkey digest) error {
	// Unauthenticated bindings are only a rejection filter; success still requires the shard proof.
	if err := verifyCompressedBindings(p, vkey); err != nil {
		return err
	}
	c := newChallenger()
	vk := &p.vk
	c.observeDigest(vk.preprocessedCommit)
	c.observeFelts(vk.pcStart[:])
	c.observeFelts(vk.globalSumX[:])
	c.observeFelts(vk.globalSumY[:])
	c.observe(vk.untrustedPrograms)
	c.observeFelts(make([]felt, 6))
	if err := verifyShard(vk, &p.shard, c); err != nil {
		return fmt.Errorf("failed to verify proof: invalid shard proof: %w", err)
	}

	return nil
}

// verifyCompressedBindings checks statement and recursion-key bindings; it does not authenticate a proof.
func verifyCompressedBindings(p *compressedProof, vkey digest) error {
	vk := &p.vk
	pv := p.shard.publicValues
	if len(pv) != numPublicValues {
		return errInvalidPublicValues
	}
	if hashFelts(pv[:pvNumHashed]) != digest(pv[pvDigest:pvDigest+digestSize]) {
		return errors.New("recursion public values are invalid")
	}

	// The proof's recursion verifying key must be in SP1's tree of recursion verifying keys.
	treeDepth := log2Ceil(vkNumKeys)
	if len(p.vkMerklePath) != treeDepth || p.vkMerkleIndex >= vkNumKeys {
		return errors.New("incorrect vkey")
	}
	node := hashFelts(vkInputs(vk))
	index := reverseBits(p.vkMerkleIndex, uint(len(p.vkMerklePath)))
	for _, sibling := range p.vkMerklePath {
		if index%2 == 0 {
			node = compress(node, sibling)
		} else {
			node = compress(sibling, node)
		}
		index >>= 1
	}
	if node != vkMerkleRoot {
		return errors.New("incorrect vkey")
	}

	if digest(pv[pvVkRoot:pvVkRoot+digestSize]) != vkMerkleRoot {
		return errors.New("vk merkle root mismatch")
	}
	if pv[pvIsComplete] != 1 {
		return errors.New("is_complete is not 1")
	}
	if digest(pv[pvSP1VkDigest:pvSP1VkDigest+digestSize]) != vkey {
		return errors.New("sp1 vk hash mismatch")
	}
	return nil
}

// vkInputs returns the field elements a verifying key's digest hashes.
func vkInputs(vk *verifyingKey) []felt {
	inputs := make([]felt, 0, digestSize+3+14+1)
	inputs = append(inputs, vk.preprocessedCommit[:]...)
	inputs = append(inputs, vk.pcStart[:]...)
	inputs = append(inputs, vk.globalSumX[:]...)
	inputs = append(inputs, vk.globalSumY[:]...)
	return append(inputs, vk.untrustedPrograms)
}
