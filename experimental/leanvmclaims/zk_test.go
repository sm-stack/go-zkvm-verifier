package leanvmclaims

import (
	"encoding/binary"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/classkey"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"os"
	"strings"
	"testing"
)

func TestZKRoots(t *testing.T) {
	f := loadFixtureSetAt(t, "testdata/zk", 23, UpstreamCommit)
	replayVerdictsAt(t, f, "testdata/zk-components.json", UpstreamCommit)
	c := f.verifier.Config()
	if len(c.Leaves) != 3 || c.Leaves[2].Kind != classkey.ZeroKnowledge || c.Leaves[2].LeafRate != 2 {
		t.Fatal("ZK class descriptor")
	}
}
func TestZKContainer(t *testing.T) {
	f := loadFixtureSetAt(t, "testdata/zk", 23, UpstreamCommit)

	var vectors struct {
		Pin   string `json:"upstream_commit"`
		Cases []struct {
			Name       string
			At         int
			Word       uint64
			Digest     string
			Accept     bool
			RootAccept bool `json:"root_accept"`
		}
	}
	fixture.JSON(t, "testdata/zk-key-vectors.json", &vectors)
	if vectors.Pin != UpstreamCommit || len(vectors.Cases) != 9 {
		t.Fatal("stale key vectors")
	}
	for _, tc := range vectors.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			key := append([]byte(nil), f.files["class-key.bin"]...)
			binary.LittleEndian.PutUint64(key[tc.At:], tc.Word)
			digest := classkey.Digest(key)
			if digest != [32]byte(fixture.Hex(t, tc.Digest)) {
				t.Fatal("Rust digest differs")
			}
			v, err := NewClassVerifier(key, digest)
			if (err == nil) != tc.Accept {
				t.Fatalf("Go load %v, Rust accepts %v", err, tc.Accept)
			}
			if err == nil {
				err = verifyEncoded(v, f.files["one-member/root.bin"], f.files["one-member/claims.bin"], f.files["one-member/seal.bin"])
				if (err == nil) != tc.RootAccept {
					t.Fatalf("Go root %v, Rust accepts %v", err, tc.RootAccept)
				}
			}
		})
	}

	bad := f.pin
	bad[0] ^= 1
	if _, err := NewClassVerifier(f.files["class-key.bin"], bad); err == nil {
		t.Fatal("wrong digest")
	}
}
func BenchmarkZKVerify(b *testing.B) {
	f := loadFixtureSetAt(b, "testdata/zk", 23, UpstreamCommit)
	for _, name := range []string{"one-member", "wide"} {
		b.Run(name, func(b *testing.B) {
			claims, err := f.verifier.DecodeClaims(f.files[name+"/claims.bin"])
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := f.verifier.VerifySealed(claims, f.files[name+"/root.bin"], f.files[name+"/seal.bin"]); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
func BenchmarkZKLoad(b *testing.B) {
	f := loadFixtureSetAt(b, "testdata/zk", 23, UpstreamCommit)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := NewClassVerifier(f.files["class-key.bin"], f.pin); err != nil {
			b.Fatal(err)
		}
	}
}

func TestOperationalKeys(t *testing.T) {
	for _, version := range []string{"v2", "v3"} {
		t.Run(version, func(t *testing.T) {
			f := loadFixtureSetAt(t, "testdata/operational-"+version, 5, UpstreamCommit)
			replayVerdictsAt(t, f, "testdata/operational-"+version+"-components.json", UpstreamCommit)
		})
	}
}
func BenchmarkOperationalZK(b *testing.B) {
	for _, version := range []string{"v2", "v3"} {
		b.Run(version, func(b *testing.B) {
			f := loadFixtureSetAt(b, "testdata/operational-"+version, 5, UpstreamCommit)
			c, err := f.verifier.DecodeClaims(f.files["production/claims.bin"])
			if err != nil {
				b.Fatal(err)
			}
			b.Run("verify", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if err := f.verifier.VerifySealed(c, f.files["production/root.bin"], f.files["production/seal.bin"]); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("load", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := NewClassVerifier(f.files["class-key.bin"], f.pin); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func TestZKOnly(t *testing.T) {
	f := loadFixtureSetAt(t, "testdata/zk-only", 14, UpstreamCommit)
	replayVerdictsAt(t, f, "testdata/zk-only-components.json", UpstreamCommit)
	if c := f.verifier.Config(); c.Small != nil || len(c.Leaves) != 1 || c.Leaves[0].Kind != ZeroKnowledgeLeaf {
		t.Fatal("ZK-only config")
	}
}
func FuzzZKDescriptor(f *testing.F) {
	corpus := loadFixtureSetAt(f, "testdata/zk", 23, UpstreamCommit)
	f.Add(uint16(1), uint64(0))
	f.Add(uint16(20), uint64(2))
	f.Add(uint16(56), uint64(0))
	f.Fuzz(func(t *testing.T, at uint16, word uint64) {
		key := append([]byte(nil), corpus.files["class-key.bin"]...)
		// The descriptor, roots and heights; fixed columns stay unchanged.
		offset := int(at%90) * 8
		binary.LittleEndian.PutUint64(key[offset:], word)
		v, err := NewClassVerifier(key, classkey.Digest(key))
		if err == nil {
			_ = verifyEncoded(v, corpus.files["one-member/root.bin"], corpus.files["one-member/claims.bin"], corpus.files["one-member/seal.bin"])
		}
	})
}

func TestZKReferencePin(t *testing.T) {
	for _, tc := range []struct{ path, needle string }{
		{"../../tools/leanvm-zk/Cargo.toml", `rev = "` + UpstreamCommit + `"`},
		{"../../tools/leanvm-zk/Cargo.lock", "#" + UpstreamCommit},
	} {
		data, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), tc.needle) {
			t.Fatal("Rust reference pin differs", tc.path)
		}
	}
}

func FuzzZKSealed(f *testing.F) {
	x := loadFixtureSetAt(f, "testdata/zk", 23, UpstreamCommit)
	names := []string{"one-member", "wide", "raw-zk-first"}
	for i := range names {
		f.Add(uint8(i), uint8(0), uint32(11), uint8(1), false)
	}
	f.Fuzz(func(t *testing.T, which, part uint8, at uint32, mask uint8, cut bool) {
		name := names[int(which)%len(names)]
		input := [][]byte{x.files[name+"/root.bin"], x.files[name+"/claims.bin"], x.files[name+"/seal.bin"]}
		i := int(part % 3)
		data := append([]byte(nil), input[i]...)
		offset := int(uint64(at) % uint64(len(data)))
		if cut {
			data = data[:offset]
		} else {
			data[offset] ^= mask
		}
		input[i] = data
		_ = verifyEncoded(x.verifier, input[0], input[1], input[2])
	})
}
