package leanvmclaims

import (
	"encoding/binary"
	"errors"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/classkey"
	"runtime"
	"testing"
)

func TestNilVerifier(t *testing.T) {
	for _, v := range []*ClassVerifier{nil, {}} {
		if !errors.Is(v.VerifySealed(nil, nil, nil), ErrClass) {
			t.Fatal("uninitialized verify")
		}
		if _, err := v.DecodeClaims(nil); !errors.Is(err, ErrClass) {
			t.Fatal("uninitialized decode")
		}
	}
}
func TestEncodeClaimsCanonical(t *testing.T) {
	for _, claims := range []ClaimSet{
		{{Members: [][4]uint64{{2}, {1}}}},
		{{Members: [][4]uint64{{1}, {1}}}},
		{{Label: [6]uint64{2}, Members: [][4]uint64{{1}}}, {Label: [6]uint64{1}, Members: [][4]uint64{{1}}}},
	} {
		if _, err := EncodeClaims(claims); err == nil {
			t.Fatal("noncanonical claims encoded")
		}
	}
}
func allocationBound(t *testing.T, f func() error) {
	t.Helper()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err := f()
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("oversized input accepted")
	}
	if n := after.TotalAlloc - before.TotalAlloc; n > 64<<10 {
		t.Fatalf("allocated %d bytes before rejection", n)
	}
}
func TestRejectBeforeLargeAllocation(t *testing.T) {
	f := loadFixtures(t)
	const words = 32768
	root := make([]byte, 11+24*words+8) // full statement and an empty transcript
	copy(root, []byte{'L', 'V', 'M', 'T', 22, 0, 1})
	binary.LittleEndian.PutUint32(root[7:], words)
	claims, err := f.verifier.DecodeClaims(f.files["one-zk/claims.bin"])
	if err != nil {
		t.Fatal(err)
	}
	allocationBound(t, func() error { return f.verifier.VerifySealed(claims, root, f.files["one-zk/seal.bin"]) })
	// The count matches the descriptor but no circuit records follow it.
	// Removing the byte-length guard would allocate thousands of Circuit structs.
	const shape = 24 + 3*144
	const circuitCount = shape + (6+3+2)*8 + 6*32 + 8 + 3*48
	key := append([]byte(nil), f.files["class-key.bin"][:circuitCount+8]...)
	binary.LittleEndian.PutUint64(key[shape+8:], 4096)
	binary.LittleEndian.PutUint64(key[shape+48:], 4096)
	binary.LittleEndian.PutUint64(key[circuitCount:], 3+4096-1+2+1)
	digest := classkey.Digest(key)
	allocationBound(t, func() error { _, err := NewClassVerifier(key, digest); return err })
}

func TestScratchCompatibility(t *testing.T) {
	if SetScratchCacheLimit(-1) == nil {
		t.Fatal("negative compatibility limit")
	}
	f := loadFixtures(t)
	defer SetScratchCacheLimit(24 << 20)
	for _, limit := range []int{0, 1024, 24 << 20} {
		if err := SetScratchCacheLimit(limit); err != nil {
			t.Fatal(err)
		}
		if err := verifyEncoded(f.verifier, f.files["plain-small/root.bin"], f.files["plain-small/claims.bin"], f.files["plain-small/seal.bin"]); err != nil {
			t.Fatalf("cache %d: %v", limit, err)
		}
	}
}
