package leanvm

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// fixtureDir holds the leanVM fixtures, which the Rust verifier's tests share.
const fixtureDir = "testdata"

func readFixture(t testing.TB, name string) []byte {
	data, err := os.ReadFile(filepath.Join(fixtureDir, name))
	require.NoError(t, err)
	return data
}

// fixture is a guest, a proof of one of its runs and that run's output.
type fixture struct {
	elf    []byte
	proof  []byte
	output [32]byte
}

func loadFixture(t testing.TB, elf, name string) *fixture {
	return &fixture{
		elf:    readFixture(t, elf),
		proof:  readFixture(t, name+".proof"),
		output: [32]byte(readFixture(t, name+".output")),
	}
}

// fibonacciDigest is the program digest of leanVM's fibonacci guest.
var fibonacciDigest = [32]byte{0xbc, 0x15, 0x5c, 0xdd, 0xb5, 0xac, 0x07, 0x5c, 0xdc, 0x82, 0x37, 0x55, 0xa7, 0x22, 0xad, 0x90, 0x30, 0xcb, 0x98, 0x7d, 0x1e, 0x1f, 0x54, 0x30, 0xf3, 0xb7, 0xb4, 0x0f, 0xe9, 0x07, 0xd5, 0x70}

func TestProgramDigestGoldenVector(t *testing.T) {
	digest, err := ProgramDigest(readFixture(t, "fibonacci.elf"))
	require.NoError(t, err)
	require.Equal(t, fibonacciDigest, digest)
	other, err := ProgramDigest(readFixture(t, "preimage.elf"))
	require.NoError(t, err)
	require.NotEqual(t, digest, other)
}

func TestVerifiesFixtures(t *testing.T) {
	fx := loadFixture(t, "fibonacci.elf", "fibonacci-1000")
	digest, err := Verify(fx.elf, fx.output, fx.proof)
	require.NoError(t, err)
	require.Equal(t, fibonacciDigest, digest)

	// A 2^25-word stack at rate 1/16, with hash rows.
	fx = loadFixture(t, "preimage.elf", "preimage-40000")
	digest, err = Verify(fx.elf, fx.output, fx.proof)
	require.NoError(t, err)
	want, err := ProgramDigest(fx.elf)
	require.NoError(t, err)
	require.Equal(t, want, digest)
}

func TestRejectsWrongStatement(t *testing.T) {
	fx := loadFixture(t, "fibonacci.elf", "fibonacci-1000")
	output := fx.output
	output[0] ^= 1
	_, err := Verify(fx.elf, output, fx.proof)
	require.ErrorContains(t, err, "does not verify")

	_, err = Verify(readFixture(t, "preimage.elf"), fx.output, fx.proof)
	require.ErrorContains(t, err, "does not verify")

	_, err = Verify(fx.elf[:len(fx.elf)/2], fx.output, fx.proof)
	require.ErrorIs(t, err, errNotGuest)

	tampered := bytes.Clone(fx.proof)
	tampered[len(tampered)/2] ^= 1
	_, err = Verify(fx.elf, fx.output, tampered)
	require.Error(t, err)
	_, err = Verify(fx.elf, fx.output, fx.proof[:len(fx.proof)-1])
	require.ErrorIs(t, err, errMalformedProof)
}

func BenchmarkVerify(b *testing.B) {
	fx := loadFixture(b, "fibonacci.elf", "fibonacci-1000")
	classTables()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := Verify(fx.elf, fx.output, fx.proof); err != nil {
			b.Fatal(err)
		}
	}
}

// FuzzVerify checks that no edit of a fixture proof, or of its guest, makes the verifier panic.
// Edits of a real proof reach the verifier's later stages, which random bytes never decode into.
func FuzzVerify(f *testing.F) {
	fx := loadFixture(f, "fibonacci.elf", "fibonacci-1000")
	f.Add(false, uint32(0), []byte{})
	f.Add(false, uint32(1), []byte{})
	f.Add(false, uint32(6), []byte{0xff, 0xff, 0xff, 0xff})
	f.Add(false, uint32(14), []byte{0x02})
	f.Add(false, uint32(len(fx.proof)/2), []byte{0x01})
	f.Add(false, uint32(len(fx.proof)-40), []byte{0x00, 0x00})
	f.Add(true, uint32(0x30), []byte{0x80})
	f.Add(true, uint32(4096), []byte{0x13, 0x00})
	f.Fuzz(func(t *testing.T, inElf bool, at uint32, put []byte) {
		elf, proof := fx.elf, fx.proof
		target := &proof
		if inElf {
			target = &elf
		}
		edited := bytes.Clone(*target)
		offset := int(uint64(at) % uint64(len(edited)))
		if at%3 == 0 {
			edited = edited[:offset]
		} else if at%3 == 1 {
			copy(edited[offset:], put)
		} else {
			edited = append(edited, put...)
		}
		*target = edited
		_, _ = Verify(elf, fx.output, proof)
		_, _ = ProgramDigest(elf)
	})
}

func TestConcurrentVerify(t *testing.T) {
	f := loadFixture(t, "fibonacci.elf", "fibonacci-1000")
	results := make(chan error, 2)
	for range 2 {
		go func() { _, err := Verify(f.elf, f.output, f.proof); results <- err }()
	}
	for range 2 {
		require.NoError(t, <-results)
	}
}

func BenchmarkVerifyPreimage(b *testing.B) {
	fx := loadFixture(b, "preimage.elf", "preimage-40000")
	classTables()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := Verify(fx.elf, fx.output, fx.proof); err != nil {
			b.Fatal(err)
		}
	}
}
