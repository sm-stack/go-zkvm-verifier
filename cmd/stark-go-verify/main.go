// Command stark-go-verify verifies leanVM execution or SP1 compressed proofs without CGO.
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/sm-stack/go-zkvm-verifier/leanvm"
	"github.com/sm-stack/go-zkvm-verifier/sp1"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// Exit codes: 0 accepted, 1 rejected (including malformed proof/ELF), 2 usage or I/O error.
func run(args []string, out, diagnostics io.Writer) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		if _, err := fmt.Fprintln(out, "usage: stark-go-verify {leanvm|sp1} -h"); err != nil {
			return 2
		}
		return 0
	}
	if len(args) == 0 || (args[0] != "leanvm" && args[0] != "sp1") {
		fmt.Fprintln(diagnostics, "usage: stark-go-verify {leanvm -elf FILE -output FILE | sp1 -vkey FILE -public-values FILE} -proof FILE")
		return 2
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(diagnostics)
	proofPath := fs.String("proof", "", "raw proof file")
	var first, second *string
	if args[0] == "leanvm" {
		first = fs.String("elf", "", "guest ELF file")
		second = fs.String("output", "", "32-byte output file (four little-endian u64 words)")
	} else {
		first = fs.String("vkey", "", "32-byte program key digest file (eight big-endian u32 words)")
		second = fs.String("public-values", "", "raw public values file")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *proofPath == "" || *first == "" || *second == "" {
		fs.Usage()
		return 2
	}
	inputs := make([][]byte, 3)
	for i, path := range []string{*first, *second, *proofPath} {
		limit := int64(64 << 20) // CLI transport budget; library policy is documented separately.
		fixed := (args[0] == "leanvm" && i == 1) || (args[0] == "sp1" && i == 0)
		if fixed {
			limit = 32
		}
		if args[0] == "sp1" && i == 2 {
			limit = sp1.MaxProofBytes
		}
		data, err := readBounded(path, limit)
		if err != nil {
			fmt.Fprintln(diagnostics, err)
			if errors.Is(err, errInputTooLarge) && !fixed {
				return 1
			}
			return 2
		}
		if fixed && len(data) != 32 {
			if args[0] == "leanvm" {
				fmt.Fprintln(diagnostics, "output must be exactly 32 bytes")
			} else {
				fmt.Fprintln(diagnostics, "vkey must be exactly 32 bytes in big-endian word order")
			}
			return 2
		}
		inputs[i] = data
	}
	var err error
	var digest [32]byte
	if args[0] == "leanvm" {
		digest, err = leanvm.Verify(inputs[0], [32]byte(inputs[1]), inputs[2])
	} else {
		err = sp1.Verify([32]byte(inputs[0]), inputs[1], inputs[2])
	}
	if err != nil {
		fmt.Fprintln(diagnostics, "rejected:", err)
		return 1
	}
	if args[0] == "leanvm" {
		_, err = fmt.Fprintln(out, "accepted", hex.EncodeToString(digest[:]))
	} else {
		_, err = fmt.Fprintln(out, "accepted")
	}
	if err != nil {
		fmt.Fprintln(diagnostics, err)
		return 2
	}
	return 0
}

var errInputTooLarge = errors.New("input exceeds CLI byte limit")

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil {
		return nil, err
	} else if info.Mode().IsRegular() && info.Size() > limit {
		return nil, fmt.Errorf("%s: %w (%d)", path, errInputTooLarge, limit)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: %w (%d)", path, errInputTooLarge, limit)
	}
	return b, nil
}
