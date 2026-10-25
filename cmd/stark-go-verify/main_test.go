package main

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestExitCodes(t *testing.T) {
	root := filepath.Join("..", "..")
	lean := filepath.Join(root, "leanvm", "testdata")
	args := []string{"leanvm", "-elf", filepath.Join(lean, "fibonacci.elf"), "-output", filepath.Join(lean, "fibonacci-1000.output"), "-proof", filepath.Join(lean, "fibonacci-1000.proof")}
	var out, diagnostics bytes.Buffer
	if code := run(args, &out, &diagnostics); code != 0 || !bytes.Contains(out.Bytes(), []byte("bc155cdd")) {
		t.Fatalf("code %d: %s %s", code, &out, &diagnostics)
	}
	read := func(p string) []byte {
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	write := func(n string, b []byte) string {
		p := filepath.Join(t.TempDir(), n)
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	bad := read(args[6])
	bad[len(bad)/2] ^= 1
	reject := append([]string(nil), args...)
	reject[6] = write("bad.proof", bad)
	sp := filepath.Join(root, "sp1", "testdata", "fixture")
	words := read(filepath.Join(sp, "vkey_hash.bin"))
	var key [32]byte
	for i := range 8 {
		binary.BigEndian.PutUint32(key[4*i:], binary.LittleEndian.Uint32(words[4*i:]))
	}
	r, e := gzip.NewReader(bytes.NewReader(read(filepath.Join(sp, "proof.bin.gz"))))
	if e != nil {
		t.Fatal(e)
	}
	proof, e := io.ReadAll(r)
	if e != nil {
		t.Fatal(e)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	spArgs := []string{"sp1", "-vkey", write("key.bin", key[:]), "-public-values", filepath.Join(sp, "public_values.bin"), "-proof", write("proof.bin", proof)}
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"sp1 accepts", spArgs, 0}, {"proof rejects", reject, 1},
		{"help", []string{"-h"}, 0}, {"subcommand help", []string{"sp1", "-h"}, 0},
		{"no command", nil, 2}, {"unknown", []string{"other"}, 2},
		{"missing flags", []string{"leanvm"}, 2},
		{"missing file", []string{"leanvm", "-elf", "absent", "-output", "absent", "-proof", "absent"}, 2},
		{"unknown flag", []string{"leanvm", "-unknown"}, 2},
		{"bad statement length", []string{"leanvm", "-elf", args[2], "-output", write("short", []byte{0}), "-proof", args[6]}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out.Reset()
			diagnostics.Reset()
			if got := run(tc.args, &out, &diagnostics); got != tc.want {
				t.Fatalf("want %d got %d: %s", tc.want, got, &diagnostics)
			}
		})
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestBoundedReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(128 << 20); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = readBounded(path, 32); err == nil {
		t.Fatal("accepted oversized statement")
	}
	for _, n := range []int{31, 32, 33} {
		if err = os.WriteFile(path, make([]byte, n), 0600); err != nil {
			t.Fatal(err)
		}
		b, err := readBounded(path, 32)
		if (err == nil) != (n <= 32) {
			t.Fatalf("length %d: %v", n, err)
		}
		if err == nil && len(b) != n {
			t.Fatal("wrong read length")
		}
	}
	if got := run([]string{"-h"}, brokenWriter{}, io.Discard); got != 2 {
		t.Fatalf("write failure exit %d", got)
	}
	lean := filepath.Join("..", "..", "leanvm", "testdata")
	args := []string{"leanvm", "-elf", filepath.Join(lean, "fibonacci.elf"), "-output", filepath.Join(lean, "fibonacci-1000.output"), "-proof", filepath.Join(lean, "fibonacci-1000.proof")}
	if got := run(args, brokenWriter{}, io.Discard); got != 2 {
		t.Fatalf("write failure exit %d", got)
	}
}

func TestOversizedVariableInputs(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "small")
	if err := os.WriteFile(small, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		command, flag string
		limit         int64
	}{
		{"leanvm", "-elf", 64 << 20}, {"leanvm", "-proof", 64 << 20},
		{"sp1", "-public-values", 64 << 20}, {"sp1", "-proof", 16 << 20},
	} {
		t.Run(tc.command+tc.flag, func(t *testing.T) {
			large := filepath.Join(dir, "large")
			f, err := os.Create(large)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.Truncate(tc.limit + 1); err != nil {
				t.Fatal(err)
			}
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
			flags := []string{"-elf", "-output", "-proof"}
			if tc.command == "sp1" {
				flags = []string{"-vkey", "-public-values", "-proof"}
			}
			args := []string{tc.command}
			for _, flag := range flags {
				path := small
				if flag == tc.flag {
					path = large
				}
				args = append(args, flag, path)
			}
			var diag bytes.Buffer
			if got := run(args, io.Discard, &diag); got != 1 {
				t.Fatalf("exit %d: %s", got, &diag)
			}
			if !bytes.Contains(diag.Bytes(), []byte("exceeds CLI byte limit")) {
				t.Fatal(diag.String())
			}
		})
	}
}
