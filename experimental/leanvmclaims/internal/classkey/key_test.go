package classkey

import (
	"bytes"
	"encoding/binary"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"os"
	"testing"
)

func compactKey(t testing.TB) []byte {
	t.Helper()
	_, f := fixture.Load(t, "../../testdata/compact", Pin, 20)
	return f["class-key.bin"]
}
func TestRustClassKeyVectors(t *testing.T) {
	b := compactKey(t)
	pin := Digest(b)
	if pin != [32]byte(fixture.Hex(t, "5345ead055078db8baf0dc0db0c605ccd9f32a26c8c7626b3f28d007a3d9d7ee")) {
		t.Fatal("digest mismatch")
	}
	k, e := Load(b, pin)
	if e != nil {
		t.Fatal(e)
	}
	if len(k.Layouts) != 3 || len(k.Config.Leaves) != 3 {
		t.Fatal("class shape")
	}
	wrong := pin
	wrong[0] ^= 1
	if _, e = Load(b, wrong); e != ErrDigest {
		t.Fatal(e)
	}
	for cut := 0; cut < len(b); cut++ {
		s := b[:cut]
		if _, e := Load(s, Digest(s)); e == nil {
			t.Fatalf("truncation %d accepted", cut)
		}
	}
	extra := append(bytes.Clone(b), 0)
	if _, e := Load(extra, Digest(extra)); e == nil {
		t.Fatal("trailing")
	}
	for _, version := range []byte{'2', '3'} {
		s := bytes.Clone(b)
		s[7] = version
		if _, e := Load(s, Digest(s)); e == nil {
			t.Fatal("old magic")
		}
	}
}
func TestClassContainerGuards(t *testing.T) {
	b := compactKey(t)
	for _, m := range []struct {
		at int
		v  uint64
	}{{8, 0}, {16, 0}, {16, ^uint64(0)}, {24 + 17*8, 2}, {24 + 3*144 + 5*8, 2}} {
		s := bytes.Clone(b)
		binary.LittleEndian.PutUint64(s[m.at:], m.v)
		if _, e := Load(s, Digest(s)); e == nil {
			t.Fatalf("accepted %+v", m)
		}
	}
}
func FuzzSemanticClass(f *testing.F) {
	f.Add(compactKey(f))
	_, shared := fixture.Load(f, "../../testdata/shared", Pin, 12)
	f.Add(shared["class-key.bin"])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Load(b, Digest(b)) })
}

func TestReferencePin(t *testing.T) {
	for _, file := range []string{"Cargo.toml", "Cargo.lock"} {
		b, e := os.ReadFile("../../../../tools/leanvm-mixed/" + file)
		if e != nil {
			t.Fatal(e)
		}
		marker := `rev = "` + Pin + `"`
		if file == "Cargo.lock" {
			marker = "#" + Pin
		}
		if !bytes.Contains(b, []byte(marker)) {
			t.Fatal("Rust reference pin differs", file)
		}
	}
}
