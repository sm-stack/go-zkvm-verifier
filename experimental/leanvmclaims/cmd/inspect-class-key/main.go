// Development tool for class-key wire comparison, not a proof verifier.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/classkey"
	"os"
)

func main() {
	path := flag.String("key", "", "class-key.bin from trusted Rust setup")
	pinText := flag.String("digest", "", "expected 32-byte class-key digest, hex")
	flag.Parse()
	if *path == "" || *pinText == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	b, e := os.ReadFile(*path)
	if e != nil {
		fail(e)
	}
	pin, e := hex.DecodeString(*pinText)
	if e != nil || len(pin) != 32 {
		fail(fmt.Errorf("digest must be 64 hex characters"))
	}
	// A wire-inspection tool can obtain its descriptor from authenticated bytes.
	// The future ClassVerifier must compare a separately supplied ClassConfig.
	if len(b) < 192 {
		fail(classkey.ErrEncoding)
	}
	end := 192
	if binary.LittleEndian.Uint64(b[176:184]) == 1 {
		end = 216
	}
	if len(b) < end {
		fail(classkey.ErrEncoding)
	}
	k, e := classkey.Decode(b, [32]byte(pin), b[8:end])
	if e != nil {
		fail(e)
	}
	if e = json.NewEncoder(os.Stdout).Encode(map[string]any{"wire_decoded": true, "semantic_validation": false,
		"proof_verification": false, "digest": hex.EncodeToString(k.Digest[:]), "bytes": len(b), "tiers": len(k.Heights), "circuits": len(k.Circuits)}); e != nil {
		fail(e)
	}
}
func fail(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(1) }
