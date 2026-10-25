// Mirrors rec/tree/design.rs::position and seal.rs::fixed_polys.
package leanvmclaims

import (
	"encoding/binary"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/classkey"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/settlement"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/wire"
	"testing"
)

func TestClassAndKindBindings(t *testing.T) {
	f := loadFixtures(t)
	for _, name := range []string{"first", "first-class1", "small-node", "wide"} {
		root := append([]byte(nil), f.files[name+"/root.bin"]...)
		root[11] ^= 1 // first/node marker must agree with authenticated circuit position
		if verifyEncoded(f.verifier, root, f.files[name+"/claims.bin"], f.files[name+"/seal.bin"]) == nil {
			t.Fatal("wrong kind accepted", name)
		}
	}
	key := append([]byte(nil), f.files["class-key.bin"]...)
	key[7] ^= 1
	if _, err := NewClassVerifier(key, classkey.Digest(key)); err == nil {
		t.Fatal("unsupported key version accepted")
	}
	for _, offset := range []int{16 + 32, 16 + 136 + 32} { // K of each authenticated leaf class
		key = append([]byte(nil), f.files["class-key.bin"]...)
		key[offset] ^= 1
		if _, err := NewClassVerifier(key, f.pin); err == nil {
			t.Fatal("changed member capacity accepted")
		}
	}
	key = append([]byte(nil), f.files["class-key.bin"]...)
	a := append([]byte(nil), key[16:152]...)
	copy(key[16:152], key[152:288])
	copy(key[152:288], a)
	if _, err := NewClassVerifier(key, f.pin); err == nil {
		t.Fatal("reordered classes accepted")
	}
}
func TestFirstLevelSealSessionException(t *testing.T) {
	f := loadFixtures(t)
	changed := *f.verifier.class
	changed.SealSession[0] ^= 1
	for _, name := range []string{"first", "first-class1", "small-node", "wide"} {
		root, err := wire.DecodeRoot(f.files[name+"/root.bin"])
		if err != nil {
			t.Fatal(err)
		}
		seal, err := transcript.Decode(f.files[name+"/seal.bin"])
		if err != nil {
			t.Fatal(err)
		}
		err = settlement.Seal(&changed, root, seal)
		first := name == "first" || name == "first-class1"
		if (err == nil) != first {
			t.Fatalf("%s wrong-session seal: %v", name, err)
		}
	}
}
func TestAuthenticatedAllocationBounds(t *testing.T) {
	f := loadFixtures(t)
	// There are enough encoded bytes for these counts, but this class disallows them.
	claims := make([]byte, 4+52*5)
	binary.LittleEndian.PutUint32(claims, 5)
	if _, err := f.verifier.DecodeClaims(claims); err == nil {
		t.Fatal("group bound")
	}
	root := append([]byte(nil), f.files["first/root.bin"]...)
	binary.LittleEndian.PutUint32(root[7:], uint32(f.verifier.class.StatementWords+1))
	if verifyEncoded(f.verifier, root, f.files["first/claims.bin"], f.files["first/seal.bin"]) == nil {
		t.Fatal("statement bound")
	}
}
