package main

import (
	"bytes"
	"encoding/hex"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims"
	"github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLeanVMClaimsCLI(t *testing.T) { testClaimsCLI(t, "compact", leanvmclaims.UpstreamCommit, 20) }

func testClaimsCLI(t *testing.T, corpus, pin string, count int) {
	base := filepath.Join("..", "..", "experimental", "leanvmclaims", "testdata", corpus)
	_, files := testutil.Load(t, base, pin, count)
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
	root := unpack("one-zk/root.bin")
	claims := unpack("one-zk/claims.bin")
	seal := unpack("one-zk/seal.bin")
	args := []string{"leanvm-claims", "-class-key", key, "-digest", hex.EncodeToString(files["class-key.digest"]), "-root", root, "-claims", claims, "-seal", seal}
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
	for _, name := range []string{"plain-small", "plain-large", "mixed-zk"} {
		node := append([]string(nil), args...)
		node[6] = unpack(name + "/root.bin")
		node[8] = unpack(name + "/claims.bin")
		node[10] = unpack(name + "/seal.bin")
		check(node, 0)
		broken := append([]byte(nil), files[name+"/seal.bin"]...)
		broken[len(broken)-1] ^= 1
		if err := os.WriteFile(node[10], broken, 0600); err != nil {
			t.Fatal(err)
		}
		check(node, 1)
	}
	unpack("one-zk/root.bin")
	unpack("one-zk/claims.bin")
	unpack("one-zk/seal.bin")

	for _, index := range []int{2, 6, 8, 10} {
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
	if diagnostic := check(bad, 2); !strings.Contains(diagnostic, "invalid class key or digest:") {
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
}

func TestClaimsRegularFiles(t *testing.T) {
	for _, path := range []string{os.DevNull, t.TempDir()} {
		if _, err := readClaimsFile(path); err == nil {
			t.Fatalf("accepted non-regular file %s", path)
		}
	}
}

func TestSharedClaimsCLI(t *testing.T) {
	_, files := testutil.Load(t, "../../experimental/leanvmclaims/testdata/shared", leanvmclaims.UpstreamCommit, 12)
	dir := t.TempDir()
	for _, name := range []string{"class-key.bin", "root.bin", "claims.bin", "seal.bin"} {
		if e := os.WriteFile(filepath.Join(dir, name), files[name], 0600); e != nil {
			t.Fatal(e)
		}
	}
	args := []string{"leanvm-claims", "-class-key", filepath.Join(dir, "class-key.bin"), "-digest", hex.EncodeToString(files["class-key.digest"]), "-root", filepath.Join(dir, "root.bin"), "-claims", filepath.Join(dir, "claims.bin"), "-seal", filepath.Join(dir, "seal.bin")}
	var out, diag bytes.Buffer
	if code := run(args, &out, &diag); code != 0 {
		t.Fatalf("exit %d: %s", code, &diag)
	}
	if e := os.WriteFile(filepath.Join(dir, "class-key.bin"), files["isolated-key.bin"], 0600); e != nil {
		t.Fatal(e)
	}
	if code := run(args, &out, &diag); code != 2 {
		t.Fatalf("wrong placement key: exit %d", code)
	}
}
