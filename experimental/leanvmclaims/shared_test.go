package leanvmclaims

import (
	"bytes"
	"encoding/binary"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/classkey"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"strings"
	"sync"
	"testing"
)

func sharedFixtures(t testing.TB) fixtures {
	t.Helper()
	_, files := fixture.Load(t, "testdata/shared", UpstreamCommit, 12)
	pin := [32]byte(files["class-key.digest"])
	v, e := NewClassVerifierWithPlacement(files["class-key.bin"], pin, ZKShared)
	if e != nil {
		t.Fatal(e)
	}
	return fixtures{files, pin, v}
}
func TestSharedConformance(t *testing.T) {
	f := sharedFixtures(t)
	c := f.verifier.Config()
	if c.Placement != ZKShared || c.Small != nil || c.TreeRate != 3 || c.Claims != 4097 || c.Groups != 64 || len(f.verifier.class.Layouts) != 1 || len(f.verifier.class.Places) != 4 {
		t.Fatal("unexpected shared class")
	}
	if f.pin != [32]byte(fixture.Hex(t, "7da486eb212493df9593d444446659925963892196008510f7a12159d67b9a18")) {
		t.Fatal("wrong class pin")
	}
	for i, p := range f.verifier.class.Places {
		if p.Tier != 0 || p.First != (i < 3) {
			t.Fatal("shared circuit order")
		}
	}
	n := 0
	for _, line := range strings.Split(string(f.files["verdicts.tsv"]), "\n") {
		p := strings.Fields(line)
		if len(p) != 7 || p[0] == "name" {
			continue
		}
		n++
		t.Run(p[0], func(t *testing.T) {
			v, e := NewClassVerifierWithPlacement(f.files[p[2]], [32]byte(f.files[p[3]]), ZKShared)
			if e == nil {
				e = verifyEncoded(v, f.files[p[4]], f.files[p[5]], f.files[p[6]])
			}
			if (e == nil) != (p[1] == "accept") {
				t.Fatalf("Rust %s; Go %v", p[1], e)
			}
		})
	}
	if n != 5 {
		t.Fatal("missing fixtures")
	}
	v, e := NewClassVerifier(f.files["class-key.bin"], f.pin)
	if e != nil {
		t.Fatal(e)
	}
	if e = verifyEncoded(v, f.files["root.bin"], f.files["claims.bin"], f.files["seal.bin"]); e != nil {
		t.Fatal(e)
	}
}
func TestSharedRustMutations(t *testing.T) {
	f := sharedFixtures(t)
	var v struct {
		Pin     string `json:"upstream_commit"`
		Loaders []struct {
			Placement, Key string
			Accept         bool
		}
		Mutations []struct {
			Action string
			Accept bool
		}
	}
	fixture.JSON(t, "testdata/shared-mutations.json", &v)
	if v.Pin != UpstreamCommit || len(v.Loaders) != 4 || len(v.Mutations) != 3 {
		t.Fatal("stale vectors")
	}
	for _, c := range v.Loaders {
		p := ZKShared
		if c.Placement == "isolated" {
			p = ZKIsolated
		}
		key := f.files[c.Key]
		_, e := NewClassVerifierWithPlacement(key, classkey.Digest(key), p)
		if (e == nil) != c.Accept {
			t.Fatalf("%s/%s: %v", c.Placement, c.Key, e)
		}
	}
	for _, m := range v.Mutations {
		r := bytes.Clone(f.files["root.bin"])
		s := f.files["seal.bin"]
		n := int(binary.LittleEndian.Uint32(r[7:]))
		at := 11 + 24*(3+f.verifier.class.DensePointVars+f.verifier.class.Polynomials)
		switch m.Action {
		case "usage-extra":
			r = append(r[:at], append(make([]byte, 24), r[at:]...)...)
			binary.LittleEndian.PutUint32(r[7:], uint32(n+1))
		case "usage-missing":
			r = append(r[:at], r[at+24:]...)
			binary.LittleEndian.PutUint32(r[7:], uint32(n-1))
		case "second-opening":
			p, e := transcript.Decode(s)
			if e != nil {
				t.Fatal(e)
			}
			p.Messages = append(bytes.Clone(p.Messages), p.Messages[8+102*24:]...)
			p.Hints = append(bytes.Clone(p.Hints), p.Hints...)
			s = encode(p)
		default:
			t.Fatal(m.Action)
		}
		e := verifyEncoded(f.verifier, r, f.files["claims.bin"], s)
		if (e == nil) != m.Accept {
			t.Fatalf("%s: %v", m.Action, e)
		}
	}
}
func BenchmarkSharedLoad(b *testing.B) {
	f := sharedFixtures(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, e := NewClassVerifier(f.files["class-key.bin"], f.pin); e != nil {
			b.Fatal(e)
		}
	}
}
func BenchmarkSharedVerify(b *testing.B) {
	f := sharedFixtures(b)
	c, e := f.verifier.DecodeClaims(f.files["claims.bin"])
	if e != nil {
		b.Fatal(e)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if e := f.verifier.VerifySealed(c, f.files["root.bin"], f.files["seal.bin"]); e != nil {
			b.Fatal(e)
		}
	}
}

func FuzzSharedSealed(f *testing.F) {
	x := sharedFixtures(f)
	valid := [][]byte{x.files["root.bin"], x.files["claims.bin"], x.files["seal.bin"]}
	f.Add(uint8(0), uint32(11), uint8(1))
	f.Add(uint8(2), uint32(2456), uint8(128))
	f.Fuzz(func(t *testing.T, part uint8, at uint32, mask uint8) {
		inputs := append([][]byte(nil), valid...)
		i := int(part % 3)
		inputs[i] = bytes.Clone(inputs[i])
		inputs[i][uint64(at)%uint64(len(inputs[i]))] ^= mask
		_ = verifyEncoded(x.verifier, inputs[0], inputs[1], inputs[2])
	})
}

func TestPlacementAuthentication(t *testing.T) {
	f := sharedFixtures(t)
	key := bytes.Clone(f.files["class-key.bin"])
	binary.LittleEndian.PutUint64(key[8:], 1)
	if _, e := NewClassVerifier(key, f.pin); e == nil {
		t.Fatal("placement not authenticated")
	}
	if _, e := NewClassVerifierWithPlacement(f.files["class-key.bin"], f.pin, ZKPlacement(2)); e == nil {
		t.Fatal("invalid placement enum")
	}
	for _, n := range []uint64{2, ^uint64(0)} {
		binary.LittleEndian.PutUint64(key[8:], n)
		if _, e := NewClassVerifier(key, classkey.Digest(key)); e == nil {
			t.Fatal("invalid placement encoding")
		}
	}
}

func TestSharedConcurrent(t *testing.T) {
	f := sharedFixtures(t)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			if e := verifyEncoded(f.verifier, f.files["root.bin"], f.files["claims.bin"], f.files["seal.bin"]); e != nil {
				t.Error(e)
			}
		})
	}
	wg.Wait()
}
