package leanvmclaims

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"sync"
	"testing"

	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
)

type fixtures struct {
	files    map[string][]byte
	pin      [32]byte
	verifier *ClassVerifier
}

func loadFixtures(t testing.TB) fixtures {
	return loadFixtureSet(t, "testdata/roots", 20)
}
func loadFixtureSet(t testing.TB, path string, count int) fixtures {
	t.Helper()
	_, files := fixture.Load(t, path, UpstreamCommit, count)
	f := fixtures{files: files}
	pin, err := hex.DecodeString(string(files["class-key.digest"]))
	if err != nil || len(pin) != 32 {
		t.Fatal("fixture digest", err)
	}
	f.pin = [32]byte(pin)
	f.verifier, err = NewClassVerifier(files["class-key.bin"], f.pin)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func verifyEncoded(v *ClassVerifier, root, claimBytes, seal []byte) error {
	claims, err := v.DecodeClaims(claimBytes)
	if err != nil {
		return errors.Join(ErrProof, err)
	}
	return v.VerifySealed(claims, root, seal)
}
func encode(p transcript.Proof) []byte {
	out := binary.LittleEndian.AppendUint64(nil, uint64(len(p.Messages)))
	out = append(out, p.Messages...)
	return append(out, p.Hints...)
}
func TestRustSealedVerdicts(t *testing.T) {
	replayVerdicts(t, loadFixtures(t), "testdata/root-components.json")
}
func replayVerdicts(t *testing.T, f fixtures, path string) {
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
	if vectors.Pin != UpstreamCommit || len(vectors.Cases) != (len(f.files)-2)/3 {
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
func TestClassTrustAndOwnership(t *testing.T) {
	f := loadFixtures(t)
	bad := f.pin
	bad[0] ^= 1
	if _, err := NewClassVerifier(f.files["class-key.bin"], bad); !errors.Is(err, ErrClass) {
		t.Fatal("wrong trusted pin accepted")
	}
	clear(f.files["class-key.bin"])
	if err := verifyEncoded(f.verifier, f.files["first/root.bin"], f.files["first/claims.bin"], f.files["first/seal.bin"]); err != nil {
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
	valid := [][]byte{f.files["first/root.bin"], f.files["first/claims.bin"], f.files["first/seal.bin"]}
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
			for _, name := range []string{"first", "first-class1", "wide"} {
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
	valid := [][]byte{x.files["first/root.bin"], x.files["first/claims.bin"], x.files["first/seal.bin"]}
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
		inputs := [][]byte{x.files["first/root.bin"], x.files["first/claims.bin"], x.files["first/seal.bin"]}
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
		if err := verifyEncoded(f.verifier, f.files["wide/root.bin"], f.files["wide/claims.bin"], f.files["wide/seal.bin"]); err != nil {
			b.Fatal(err)
		}
	}
}

func TestFirstSmallAndWide(t *testing.T) {
	f := loadFixtures(t)
	for i, name := range []string{"first", "small-node", "wide"} {
		root := f.files[name+"/root.bin"]
		claims := f.files[name+"/claims.bin"]
		seal := f.files[name+"/seal.bin"]
		if binary.LittleEndian.Uint64(root[11:]) != []uint64{0, 5, 9}[i] {
			t.Fatal("wrong circuit kind in fixture")
		}
		if err := verifyEncoded(f.verifier, root, claims, seal); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		bad := append(append([]byte(nil), seal...), 0)
		if verifyEncoded(f.verifier, root, claims, bad) == nil {
			t.Fatalf("%s accepted trailing seal", name)
		}
	}
}

func TestRustOneTierVerdicts(t *testing.T) {
	replayVerdicts(t, loadFixtureSet(t, "testdata/one-tier", 14), "testdata/one-tier-components.json")
}
