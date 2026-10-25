package blake

import (
	"encoding/binary"
	"golang.org/x/crypto/blake2s"
	"testing"
)

func TestCompressionAgainstBLAKE2s(t *testing.T) {
	for n := 0; n <= 599; n++ {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i*37 + n)
		}
		cv := ParameterIV()
		rest := data
		var count uint64
		for len(rest) > 64 {
			cv = Compress(cv, [64]byte(rest[:64]), count+64, false)
			count += 64
			rest = rest[64:]
		}
		var block [64]byte
		copy(block[:], rest)
		cv = Compress(cv, block, count+uint64(len(rest)), true)
		var got [32]byte
		for i, v := range cv {
			binary.LittleEndian.PutUint32(got[i*4:], v)
		}
		if got != blake2s.Sum256(data) {
			t.Fatalf("length %d", n)
		}
	}
}
