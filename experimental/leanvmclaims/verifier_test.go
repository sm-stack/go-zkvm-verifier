package leanvmclaims

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
)

type fixtures struct {
	files    map[string][]byte
	config   ClassConfig
	pin      [32]byte
	verifier *ClassVerifier
}

func loadFixtures(t testing.TB) fixtures {
	return loadFixtureSet(t, "testdata/roots", "de82c3471f61accaa408d475404d7cd911edf04f23873a5d0f4fb9a2344ae171", ClassConfig{LogBytecode: 12, LogRAM: 17, LogAdvice: 13, ImageWords: 64, LeafHeights: [11]uint64{15, 4, 4, 6, 7, 5, 4, 4, 4, 3, 3}, LeafRate: 1, Arity0: 2, Arity: 2, TreeRate: 1, Claims: 8, Groups: 4})
}
func loadFixtureSet(t testing.TB, base string, expectedPin string, config ClassConfig) fixtures {
	t.Helper()
	var manifest struct {
		Pin   string `json:"upstream_commit"`
		Files map[string]struct {
			Bytes int
			Hash  string `json:"sha256"`
		}
	}
	b, err := os.ReadFile(filepath.Join(base, "provenance.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Pin != UpstreamCommit || len(manifest.Files) != 12 {
		t.Fatal("invalid root fixture provenance")
	}
	f := fixtures{files: make(map[string][]byte), config: config}
	for name, e := range manifest.Files {
		file, err := os.Open(filepath.Join(base, name+".gz"))
		if err != nil {
			t.Fatal(err)
		}
		gz, err := gzip.NewReader(file)
		if err != nil {
			file.Close()
			t.Fatal(err)
		}
		raw, err := io.ReadAll(io.LimitReader(gz, int64(e.Bytes)+1))
		gz.Close()
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if len(raw) != e.Bytes || hex.EncodeToString(sum[:]) != e.Hash {
			t.Fatalf("corrupt fixture %s", name)
		}
		f.files[name] = raw
	}
	pin, err := hex.DecodeString(expectedPin)
	if err != nil {
		t.Fatal(err)
	}
	f.pin = [32]byte(pin)
	f.verifier, err = NewClassVerifier(f.files["class-key.bin"], f.pin, f.config)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func encode(p transcript.Proof) []byte {
	out := binary.LittleEndian.AppendUint64(nil, uint64(len(p.Messages)))
	out = append(out, p.Messages...)
	return append(out, p.Hints...)
}
func TestRustSealedVerdicts(t *testing.T) {
	replayVerdicts(t, loadFixtures(t), "testdata/root-components.json")
}
func TestRustTierVerdicts(t *testing.T) {
	replayVerdicts(t, loadTierFixtures(t), "testdata/tier-verdicts.json")
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
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Pin != UpstreamCommit || len(vectors.Cases) != 3 {
		t.Fatal("stale root verdicts")
	}
	for _, c := range vectors.Cases {
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
				if c.Name == other {
					other = vectors.Cases[1].Name
				}
				seal = f.files[other+"/seal.bin"]
			default:
				t.Fatalf("unhandled Rust vector: %s", v.Action)
			}
			err = f.verifier.VerifySealed(root, claims, seal)
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
	if _, err := NewClassVerifier(f.files["class-key.bin"], bad, f.config); !errors.Is(err, ErrClass) {
		t.Fatal("wrong trusted pin accepted")
	}
	c := f.config
	c.Claims++
	if _, err := NewClassVerifier(f.files["class-key.bin"], f.pin, c); !errors.Is(err, ErrClass) {
		t.Fatal("wrong expected class accepted")
	}
	clear(f.files["class-key.bin"])
	if err := f.verifier.VerifySealed(f.files["distinct-1/root.bin"], f.files["distinct-1/claims.bin"], f.files["distinct-1/seal.bin"]); err != nil {
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
	valid := [][]byte{f.files["distinct-1/root.bin"], f.files["distinct-1/claims.bin"], f.files["distinct-1/seal.bin"]}
	for part := range valid {
		for _, cut := range []int{0, 1, 7, len(valid[part]) / 2, len(valid[part]) - 1} {
			inputs := append([][]byte(nil), valid...)
			inputs[part] = inputs[part][:cut]
			if err := f.verifier.VerifySealed(inputs[0], inputs[1], inputs[2]); !errors.Is(err, ErrProof) {
				t.Fatalf("part%d cut%d: %v", part, cut, err)
			}
		}
		inputs := append([][]byte(nil), valid...)
		inputs[part] = append(append([]byte(nil), inputs[part]...), 0)
		if f.verifier.VerifySealed(inputs[0], inputs[1], inputs[2]) == nil {
			t.Fatalf("part%d trailing accepted", part)
		}
	}
	root := append([]byte(nil), valid[0]...)
	root[19] = 1 // non-base-field circuit tag
	if f.verifier.VerifySealed(root, valid[1], valid[2]) == nil {
		t.Fatal("noncanonical circuit tag accepted")
	}
}
func TestConcurrentVerify(t *testing.T) {
	f := loadFixtures(t)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			for _, name := range []string{"distinct-1", "distinct-2", "distinct-4"} {
				if err := f.verifier.VerifySealed(f.files[name+"/root.bin"], f.files[name+"/claims.bin"], f.files[name+"/seal.bin"]); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
}
func FuzzVerifySealed(f *testing.F) {
	x := loadFixtures(f)
	valid := [][]byte{x.files["distinct-1/root.bin"], x.files["distinct-1/claims.bin"], x.files["distinct-1/seal.bin"]}
	f.Add(uint8(0), uint32(0), uint8(1))
	f.Add(uint8(2), uint32(100), uint8(128))
	f.Fuzz(func(t *testing.T, part uint8, at uint32, mask uint8) {
		inputs := append([][]byte(nil), valid...)
		i := int(part % 3)
		inputs[i] = append([]byte(nil), inputs[i]...)
		inputs[i][int(uint64(at)%uint64(len(inputs[i])))] ^= mask
		_ = x.verifier.VerifySealed(inputs[0], inputs[1], inputs[2])
	})
}
func FuzzMalformedSealed(f *testing.F) {
	x := loadFixtures(f)
	f.Add([]byte{}, uint8(0))
	f.Add([]byte("LVMT"), uint8(1))
	f.Fuzz(func(t *testing.T, b []byte, part uint8) {
		inputs := [][]byte{x.files["distinct-1/root.bin"], x.files["distinct-1/claims.bin"], x.files["distinct-1/seal.bin"]}
		inputs[int(part%3)] = b
		_ = x.verifier.VerifySealed(inputs[0], inputs[1], inputs[2])
	})
}
func BenchmarkClassLoad(b *testing.B) {
	f := loadFixtures(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := NewClassVerifier(f.files["class-key.bin"], f.pin, f.config); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkVerifySealed(b *testing.B) {
	f := loadFixtures(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := f.verifier.VerifySealed(f.files["distinct-4/root.bin"], f.files["distinct-4/claims.bin"], f.files["distinct-4/seal.bin"]); err != nil {
			b.Fatal(err)
		}
	}
}

func loadTierFixtures(t testing.TB) fixtures {
	return loadFixtureSet(t, "testdata/tiers", "325f58be52f490b65215f80ad7a6da899f91d252db7edcadd4bb97f1d2432579", ClassConfig{LogBytecode: 12, LogRAM: 4, LogAdvice: 4, ImageWords: 1, LeafHeights: [11]uint64{4, 4, 4, 5, 5, 4, 4, 4, 4, 3, 3}, LeafRate: 1, Arity0: 2, Arity: 2, TreeRate: 1, Claims: 8, Groups: 4, Small: &SmallTier{Arity: 2, Claims: 4, Groups: 2}})
}
func TestFirstSmallAndWide(t *testing.T) {
	f := loadTierFixtures(t)
	for i, name := range []string{"first", "small-node", "wide"} {
		root := f.files[name+"/root.bin"]
		claims := f.files[name+"/claims.bin"]
		seal := f.files[name+"/seal.bin"]
		if binary.LittleEndian.Uint64(root[11:]) != []uint64{0, 1, 4}[i] {
			t.Fatal("wrong circuit kind in fixture")
		}
		if err := f.verifier.VerifySealed(root, claims, seal); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		bad := append(append([]byte(nil), seal...), 0)
		if f.verifier.VerifySealed(root, claims, bad) == nil {
			t.Fatalf("%s accepted trailing seal", name)
		}
	}
	f.config.Small.Claims = 100
	if err := f.verifier.VerifySealed(f.files["wide/root.bin"], f.files["wide/claims.bin"], f.files["wide/seal.bin"]); err != nil {
		t.Fatal("retained caller's Small pointer", err)
	}
}
