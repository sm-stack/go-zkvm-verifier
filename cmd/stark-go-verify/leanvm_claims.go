package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims"
)

func runLeanVMClaims(args []string, out, diagnostics io.Writer) int {
	fs := flag.NewFlagSet("leanvm-claims", flag.ContinueOnError)
	fs.SetOutput(diagnostics)
	fs.Usage = func() {
		fmt.Fprintln(diagnostics, "usage: stark-go-verify leanvm-claims [flags]")
		fmt.Fprintln(diagnostics, "Experimental sealed claim-tree verification for the pinned sm-stack leanVM fork.")
		fs.PrintDefaults()
	}
	keyPath := fs.String("class-key", "", "raw LVMXCK01 class-key file")
	digestHex := fs.String("digest", "", "independently trusted class-key digest (64 hex characters)")
	configPath := fs.String("class", "", "expected ClassConfig JSON file")
	rootPath := fs.String("root", "", "raw version-20 claim-tree root file")
	claimPath := fs.String("claims", "", "raw claim-set file")
	sealPath := fs.String("seal", "", "raw v2 seal file")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *keyPath == "" || *digestHex == "" || *configPath == "" || *rootPath == "" || *claimPath == "" || *sealPath == "" {
		fs.Usage()
		return 2
	}
	digest, err := hex.DecodeString(*digestHex)
	if err != nil || len(digest) != 32 {
		fmt.Fprintln(diagnostics, "digest must be exactly 64 hex characters")
		return 2
	}
	configBytes, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintln(diagnostics, err)
		return 2
	}
	var config *leanvmclaims.ClassConfig
	decoder := json.NewDecoder(bytes.NewReader(configBytes))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&config); err != nil || config == nil {
		fmt.Fprintln(diagnostics, "invalid expected class:", err)
		return 2
	}
	var trailing any
	if err = decoder.Decode(&trailing); err != io.EOF {
		fmt.Fprintln(diagnostics, "expected class must contain one JSON object")
		return 2
	}
	paths := []string{*keyPath, *rootPath, *claimPath, *sealPath}
	inputs := make([][]byte, len(paths))
	// Claim-tree class sizes vary with the circuit. Match library/upstream acceptance
	// without introducing a transport cap specific to this CLI subcommand.
	for i, path := range paths {
		inputs[i], err = os.ReadFile(path)
		if err != nil {
			fmt.Fprintln(diagnostics, err)
			return 2
		}
	}
	verifier, err := leanvmclaims.NewClassVerifier(inputs[0], [32]byte(digest), *config)
	if err == nil {
		err = verifier.VerifySealed(inputs[1], inputs[2], inputs[3])
	}
	if err != nil {
		fmt.Fprintln(diagnostics, "rejected:", err)
		return 1
	}
	if _, err = fmt.Fprintln(out, "accepted"); err != nil {
		fmt.Fprintln(diagnostics, err)
		return 2
	}
	return 0
}
