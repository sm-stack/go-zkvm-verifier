package leanvmclaims

import (
	"encoding/binary"
	"errors"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"strings"
	"sync"
	"testing"
)

type fixtures struct {
	files    map[string][]byte
	pin      [32]byte
	verifier *ClassVerifier
}

func loadFixtures(t testing.TB) fixtures {
	t.Helper()
	_, files := fixture.Load(t, "testdata/compact", UpstreamCommit, 20)
	pin := [32]byte(files["class-key.digest"])
	v, e := NewClassVerifier(files["class-key.bin"], pin)
	if e != nil {
		t.Fatal(e)
	}
	return fixtures{files, pin, v}
}
func verifyEncoded(v *ClassVerifier, root, claims, seal []byte) error {
	c, e := v.DecodeClaims(claims)
	if e != nil {
		return errors.Join(ErrProof, e)
	}
	return v.VerifySealed(c, root, seal)
}
func encode(p transcript.Proof) []byte {
	b := binary.LittleEndian.AppendUint64(nil, uint64(len(p.Messages)))
	b = append(b, p.Messages...)
	return append(b, p.Hints...)
}
func TestRustSealedVerdicts(t *testing.T) {
	f := loadFixtures(t)
	n := 0
	for _, line := range strings.Split(string(f.files["verdicts.tsv"]), "\n") {
		p := strings.Fields(line)
		if len(p) != 7 || p[0] == "name" || strings.HasPrefix(p[0], "#") {
			continue
		}
		n++
		t.Run(p[0], func(t *testing.T) {
			v, e := NewClassVerifier(f.files[p[2]], [32]byte(f.files[p[3]]))
			if e == nil {
				e = verifyEncoded(v, f.files[p[4]], f.files[p[5]], f.files[p[6]])
			}
			if (e == nil) != (p[1] == "accept") {
				t.Fatalf("Rust %s; Go %v", p[1], e)
			}
		})
	}
	if n != 8 {
		t.Fatalf("missing verdicts: %d", n)
	}
}
func TestClassTrustAndOwnership(t *testing.T) {
	f := loadFixtures(t)
	bad := f.pin
	bad[0] ^= 1
	if _, err := NewClassVerifier(f.files["class-key.bin"], bad); !errors.Is(err, ErrClass) {
		t.Fatal("wrong trusted pin accepted")
	}
	clear(f.files["class-key.bin"])
	if err := verifyEncoded(f.verifier, f.files["one-zk/root.bin"], f.files["one-zk/claims.bin"], f.files["one-zk/seal.bin"]); err != nil {
		t.Fatal("caller mutation affected verifier", err)
	}
	var zero ClassVerifier
	if !errors.Is(zero.VerifySealed(nil, nil, nil), ErrClass) {
		t.Fatal("zero verifier did not reject")
	}
	if !errors.Is((*ClassVerifier)(nil).VerifySealed(nil, nil, nil), ErrClass) {
		t.Fatal("nil verifier did not reject")
	}
}
func TestMalformedInputs(t *testing.T) {
	f := loadFixtures(t)
	valid := [][]byte{f.files["one-zk/root.bin"], f.files["one-zk/claims.bin"], f.files["one-zk/seal.bin"]}
	for part := range valid {
		for _, cut := range []int{0, 1, 7, len(valid[part]) / 2, len(valid[part]) - 1} {
			inputs := append([][]byte(nil), valid...)
			inputs[part] = inputs[part][:cut]
			if err := verifyEncoded(f.verifier, inputs[0], inputs[1], inputs[2]); !errors.Is(err, ErrProof) {
				t.Fatalf("part%d cut%d: %v", part, cut, err)
			}
		}
		inputs := append([][]byte(nil), valid...)
		inputs[part] = append(append([]byte(nil), inputs[part]...), 0)
		if verifyEncoded(f.verifier, inputs[0], inputs[1], inputs[2]) == nil {
			t.Fatalf("part%d trailing accepted", part)
		}
	}
	root := append([]byte(nil), valid[0]...)
	root[19] = 1 // non-base-field circuit tag
	if verifyEncoded(f.verifier, root, valid[1], valid[2]) == nil {
		t.Fatal("noncanonical circuit tag accepted")
	}
}
func TestConcurrentVerify(t *testing.T) {
	f := loadFixtures(t)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			for _, name := range []string{"one-zk", "mixed-zk", "plain-large"} {
				if err := verifyEncoded(f.verifier, f.files[name+"/root.bin"], f.files[name+"/claims.bin"], f.files[name+"/seal.bin"]); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
}
func FuzzVerifySealed(f *testing.F) {
	x := loadFixtures(f)
	valid := [][]byte{x.files["one-zk/root.bin"], x.files["one-zk/claims.bin"], x.files["one-zk/seal.bin"]}
	f.Add(uint8(0), uint32(0), uint8(1))
	f.Add(uint8(2), uint32(100), uint8(128))
	f.Fuzz(func(t *testing.T, part uint8, at uint32, mask uint8) {
		inputs := append([][]byte(nil), valid...)
		i := int(part % 3)
		inputs[i] = append([]byte(nil), inputs[i]...)
		inputs[i][int(uint64(at)%uint64(len(inputs[i])))] ^= mask
		_ = verifyEncoded(x.verifier, inputs[0], inputs[1], inputs[2])
	})
}
func FuzzMalformedSealed(f *testing.F) {
	x := loadFixtures(f)
	f.Add([]byte{}, uint8(0))
	f.Add([]byte("LVMT"), uint8(1))
	f.Fuzz(func(t *testing.T, b []byte, part uint8) {
		inputs := [][]byte{x.files["one-zk/root.bin"], x.files["one-zk/claims.bin"], x.files["one-zk/seal.bin"]}
		inputs[int(part%3)] = b
		_ = verifyEncoded(x.verifier, inputs[0], inputs[1], inputs[2])
	})
}
func BenchmarkClassLoad(b *testing.B) {
	f := loadFixtures(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := NewClassVerifier(f.files["class-key.bin"], f.pin); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkVerifySealed(b *testing.B) {
	f := loadFixtures(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := verifyEncoded(f.verifier, f.files["plain-large/root.bin"], f.files["plain-large/claims.bin"], f.files["plain-large/seal.bin"]); err != nil {
			b.Fatal(err)
		}
	}
}

func TestRustRootComponents(t *testing.T) {
	replayVerdictsAt(t, loadFixtures(t), "testdata/compact-components.json", UpstreamCommit)
}
func replayVerdictsAt(t *testing.T, f fixtures, path, origin string) {
	var vectors struct {
		Pin   string `json:"upstream_commit"`
		Cases []struct {
			Name     string
			Verdicts []struct {
				Action string
				Cut    int
				At     int
				Accept bool
			}
		}
	}
	fixture.JSON(t, path, &vectors)
	if vectors.Pin != origin || len(vectors.Cases) != 4 {
		t.Fatal("stale root verdicts")
	}
	for index, c := range vectors.Cases {
		if len(c.Verdicts) < 38 {
			t.Fatal("missing rejection cases")
		}
		for _, v := range c.Verdicts {
			root := append([]byte(nil), f.files[c.Name+"/root.bin"]...)
			claims := append([]byte(nil), f.files[c.Name+"/claims.bin"]...)
			seal := append([]byte(nil), f.files[c.Name+"/seal.bin"]...)
			p, err := transcript.Decode(seal)
			if err != nil {
				t.Fatal(err)
			}
			switch v.Action {
			case "original":
			case "root-rate":
				if root[6] == 1 {
					root[6] = 2
				} else {
					root[6] = 1
				}
			case "root-byte-flip":
				root[v.At] ^= 1
			case "root-cut":
				root = root[:v.Cut]
			case "claims-label":
				claims[4] ^= 1
			case "matrix-value":
				n := int(binary.LittleEndian.Uint32(root[7:11]))
				root[11+24*(n-1)] ^= 1
			case "seal-cut":
				p.Messages = p.Messages[:v.Cut]
				seal = encode(p)
			case "seal-flip":
				p.Messages[len(p.Messages)-1] ^= 1
			case "seal-trailing":
				p.Messages = append(append([]byte(nil), p.Messages...), 0)
				seal = encode(p)
			case "seal-swap":
				other := vectors.Cases[0].Name
				if index < 3 {
					other = vectors.Cases[len(vectors.Cases)-1].Name
				}
				seal = f.files[other+"/seal.bin"]
			default:
				t.Fatalf("unhandled Rust vector: %s", v.Action)
			}
			err = verifyEncoded(f.verifier, root, claims, seal)
			if (err == nil) != v.Accept {
				t.Fatalf("%s/%s/%d: %v; Rust accepts=%v", c.Name, v.Action, v.Cut, err, v.Accept)
			}
		}
	}
}
