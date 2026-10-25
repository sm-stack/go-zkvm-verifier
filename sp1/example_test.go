package sp1_test

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"github.com/sm-stack/go-zkvm-verifier/sp1"
	"io"
	"os"
)

func ExampleVerify() {
	read := func(name string) []byte {
		b, err := os.ReadFile("testdata/fixture/" + name)
		if err != nil {
			panic(err)
		}
		return b
	}
	// The fixture stores little-endian bincode words; the public API takes big-endian words.
	words := read("vkey_hash.bin")
	var key [32]byte
	for i := range 8 {
		binary.BigEndian.PutUint32(key[4*i:], binary.LittleEndian.Uint32(words[4*i:]))
	}
	r, err := gzip.NewReader(bytes.NewReader(read("proof.bin.gz")))
	if err != nil {
		panic(err)
	}
	proof, err := io.ReadAll(r)
	if err != nil {
		panic(err)
	}
	r.Close()
	fmt.Println(sp1.Verify(key, read("public_values.bin"), proof) == nil)
	// Output: true
}
