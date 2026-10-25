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
	configBytes, err := readClaimsFile(*configPath)
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
	key, err := readClaimsFile(*keyPath)
	if err != nil {
		fmt.Fprintln(diagnostics, err)
		return 2
	}
	verifier, err := leanvmclaims.NewClassVerifier(key, [32]byte(digest), *config)
	if err != nil {
		fmt.Fprintln(diagnostics, "invalid class configuration:", err)
		return 2
	}
	paths := []string{*rootPath, *claimPath, *sealPath}
	inputs := make([][]byte, len(paths))
	for i, path := range paths {
		inputs[i], err = readClaimsFile(path)
		if err != nil {
			fmt.Fprintln(diagnostics, err)
			return 2
		}
	}
	err = verifier.VerifySealed(inputs[0], inputs[1], inputs[2])
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

// readClaimsFile accepts regular files and reads at most their observed size.
// This transport policy avoids unbounded device/stream reads; it does not impose
// a new maximum class or proof size on the verifier.
func readClaimsFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: expected a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: expected a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, info.Size()))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != info.Size() {
		return nil, fmt.Errorf("%s: file changed while reading", path)
	}
	var extra [1]byte
	if n, err := f.Read(extra[:]); n != 0 || err != io.EOF {
		return nil, fmt.Errorf("%s: file changed while reading", path)
	}
	return data, nil
}
