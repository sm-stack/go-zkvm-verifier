package main

import (
	"bytes"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims"
	"github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLeanVMClaimsCLI(t *testing.T) {
	base := filepath.Join("..", "..", "experimental", "leanvmclaims", "testdata", "roots")
	_, files := testutil.Load(t, base, leanvmclaims.UpstreamCommit, 12)
	dir := t.TempDir()
	unpack := func(name string) string {
		t.Helper()
		path := filepath.Join(dir, filepath.Base(name))
		if err := os.WriteFile(path, files[name], 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	key := unpack("class-key.bin")
	root := unpack("distinct-1/root.bin")
	claims := unpack("distinct-1/claims.bin")
	seal := unpack("distinct-1/seal.bin")
	config := filepath.Join(dir, "class.json")
	data := []byte(`{"LogBytecode":12,"LogRAM":17,"LogAdvice":13,"ImageWords":64,"LeafHeights":[15,4,4,6,7,5,4,4,4,3,3],"LeafRate":1,"Arity0":2,"Arity":2,"TreeRate":1,"Claims":8,"Groups":4}`)
	if err := os.WriteFile(config, data, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"leanvm-claims", "-class-key", key, "-digest", "de82c3471f61accaa408d475404d7cd911edf04f23873a5d0f4fb9a2344ae171", "-class", config, "-root", root, "-claims", claims, "-seal", seal}
	check := func(args []string, want int) string {
		t.Helper()
		var out, diag bytes.Buffer
		got := run(args, &out, &diag)
		if got != want {
			t.Fatalf("exit %d want%d: %s", got, want, &diag)
		}
		if got == 0 && len(args) > 2 && !bytes.Contains(out.Bytes(), []byte("accepted")) {
			t.Fatalf("missing accepted output: %s", &out)
		}
		return diag.String()
	}
	check(args, 0)
	for _, index := range []int{2, 6, 8, 10, 12} {
		nonregular := append([]string(nil), args...)
		nonregular[index] = os.DevNull
		check(nonregular, 2)
	}
	check([]string{"leanvm-claims", "-h"}, 0)
	check([]string{"leanvm-claims"}, 2)
	bad := append([]string(nil), args...)
	bad[4] = "00"
	check(bad, 2)
	bad = append([]string(nil), args...)
	bad[4] = "0000000000000000000000000000000000000000000000000000000000000000"
	check(bad, 2)
	bad[8] = filepath.Join(dir, "missing")
	if diagnostic := check(bad, 2); !strings.Contains(diagnostic, "invalid class configuration:") {
		t.Fatal("class authentication did not precede proof I/O:", diagnostic)
	}
	bad = append([]string(nil), args...)
	bad[8] = filepath.Join(dir, "missing")
	check(bad, 2)
	brokenKey := append([]byte(nil), files["class-key.bin"]...)
	brokenKey[0] ^= 1
	if err := os.WriteFile(key, brokenKey, 0600); err != nil {
		t.Fatal(err)
	}
	check(args, 2)
	if err := os.WriteFile(key, files["class-key.bin"], 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	check(args, 1)
	for _, badConfig := range [][]byte{[]byte("{}"), []byte("null"), []byte("{} {}"), []byte(`{"typo":1}`)} {
		if err := os.WriteFile(config, badConfig, 0600); err != nil {
			t.Fatal(err)
		}
		check(args, 2)
	}
}

func TestClaimsRegularFiles(t *testing.T) {
	for _, path := range []string{os.DevNull, t.TempDir()} {
		if _, err := readClaimsFile(path); err == nil {
			t.Fatalf("accepted non-regular file %s", path)
		}
	}
}
