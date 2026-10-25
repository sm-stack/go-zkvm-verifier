package leanvm

import "testing"

func FuzzDecodeProof(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("LVMP\x01\x00"))
	// Full proofs are exercised by FuzzVerify; small seeds keep decoder fuzzing productive.
	f.Add(append([]byte("LVMP\x01\x00"), make([]byte, 128)...))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = decodeProof(data) })
}
