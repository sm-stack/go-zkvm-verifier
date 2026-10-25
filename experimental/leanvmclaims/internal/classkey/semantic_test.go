package classkey

import (
	"encoding/binary"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"testing"
)

func configForTest() Config {
	return Config{LogBytecode: 12, LogRAM: 4, LogAdvice: 4, ImageWords: 1, LeafHeights: [11]uint64{4, 4, 4, 5, 5, 4, 4, 4, 4, 3, 3}, LeafRate: 1, Arity0: 2, Arity: 2, TreeRate: 1, Claims: 4, Groups: 4}
}
func TestSemanticClasses(t *testing.T) {
	for _, v := range vectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			cfg := configForTest()
			if v.Name == "two-tier" {
				cfg.Small = &SmallTier{2, 2, 2}
			}
			data := input(t, v)
			pin := [32]byte(fixture.Hex(t, v.Digest))
			got, err := Load(data, pin, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if v.PlaceholderDigest == "" || got.ProgramDigest != [32]byte(fixture.Hex(t, v.PlaceholderDigest)) {
				t.Fatal("Rust placeholder digest differs")
			}
			if len(v.SemanticCases) != 14 {
				t.Fatal("incomplete semantic vectors")
			}
			for _, m := range v.SemanticCases {
				changed := cfg
				switch m.Index {
				case 0:
					changed.LogBytecode = m.Value
				case 1:
					changed.LogRAM = m.Value
				case 2:
					changed.LogAdvice = m.Value
				case 3:
					changed.ImageWords = m.Value
				}
				edited := append([]byte(nil), data...)
				binary.LittleEndian.PutUint64(edited[8+8*m.Index:], m.Value)
				_, err := Load(edited, [32]byte(fixture.Hex(t, m.Digest)), changed)
				if (err == nil) != m.Accept {
					t.Fatalf("Rust class dimension %d=%d: %v (Rust %v)", m.Index, m.Value, err, m.Accept)
				}
			}
			for _, m := range v.Mutations {
				edited := append([]byte(nil), data...)
				if edited[m.Offset] == m.Value {
					t.Fatalf("ineffective mutation %s", m.Name)
				}
				edited[m.Offset] = m.Value
				_, err := Load(edited, [32]byte(fixture.Hex(t, m.Digest)), cfg)
				if (err == nil) != m.Accept {
					t.Fatalf("Rust semantic mutation %s: %v", m.Name, err)
				}
			}
			if got.StatementWords != int(got.Key.Circuits[0].StatementWords) {
				t.Fatal("statement layout differs")
			}
			// A correctly rehashed but semantically inconsistent statement size must
			// fail even though its container framing is well formed.
			desc, _ := cfg.Descriptor()
			first := 8 + len(desc) + 8 + 32*len(got.Key.Roots) + 32 + 8 + 48*len(got.Key.Roots) + 8
			binary.LittleEndian.PutUint64(data[first:], uint64(got.StatementWords+1))
			if _, err = Load(data, Digest(data), cfg); err == nil {
				t.Fatal("accepted inconsistent statement length")
			}
			if cfg.Small != nil {
				cfg.Small.Arity = 100
				if got.Config.Small.Arity != 2 {
					t.Fatal("constructor retained mutable caller config")
				}
			}
		})
	}
}
func TestInvalidClassSizes(t *testing.T) {
	for _, change := range []func(*Config){
		func(c *Config) { c.LogBytecode = 11 }, func(c *Config) { c.LogBytecode = 25 },
		func(c *Config) { c.LogRAM = 28 }, func(c *Config) { c.LogAdvice = 27 },
		func(c *Config) { c.ImageWords = 0 }, func(c *Config) { c.ImageWords = 3 }, func(c *Config) { c.ImageWords = 32 },
		func(c *Config) { c.LeafHeights[0] = 3 }, func(c *Config) { c.LeafHeights[0] = 32 },
	} {
		c := configForTest()
		change(&c)
		if _, err := Load(nil, [32]byte{}, c); err == nil || err == ErrDigest {
			t.Fatalf("class was not rejected before key load: %+v: %v", c, err)
		}
	}
}

func FuzzSemanticClass(f *testing.F) {
	f.Add([]byte("LVMXCK01"), uint8(0), uint64(12))
	f.Add([]byte{}, uint8(3), ^uint64(0))
	f.Fuzz(func(t *testing.T, data []byte, axis uint8, value uint64) {
		c := configForTest()
		switch axis % 4 {
		case 0:
			c.LogBytecode = value
		case 1:
			c.LogRAM = value
		case 2:
			c.LogAdvice = value
		case 3:
			c.ImageWords = value
		}
		_, _ = Load(data, Digest(data), c)
	})
}
