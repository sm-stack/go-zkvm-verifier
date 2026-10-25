// Mirrors rec/tree/embed.rs checked loading and cpu/key.rs placeholder digest.
package classkey

import (
	"encoding/binary"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"testing"
)

func TestSemanticClasses(t *testing.T) {
	for _, v := range vectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			data := input(t, v)
			pin := [32]byte(fixture.Hex(t, v.Digest))
			got, err := Load(data, pin)
			if err != nil {
				t.Fatal(err)
			}
			if got.ProgramDigest != [32]byte(fixture.Hex(t, v.PlaceholderDigest)) {
				t.Fatal("Rust placeholder digest differs")
			}
			if len(v.SemanticCases) != 14 {
				t.Fatal("missing semantic cases")
			}
			for _, m := range v.SemanticCases {
				edited := append([]byte(nil), data...)
				binary.LittleEndian.PutUint64(edited[16+8*m.Index:], m.Value)
				_, err := Load(edited, [32]byte(fixture.Hex(t, m.Digest)))
				if (err == nil) != m.Accept {
					t.Fatalf("dimension %d=%d: %v, Rust %v", m.Index, m.Value, err, m.Accept)
				}
			}
			for _, m := range v.Mutations {
				edited := append([]byte(nil), data...)
				edited[m.Offset] = m.Value
				_, err := Load(edited, [32]byte(fixture.Hex(t, m.Digest)))
				if (err == nil) != m.Accept {
					t.Fatalf("mutation %s: %v, Rust %v", m.Name, err, m.Accept)
				}
			}
			if got.Codes[0] != 0 || got.Codes[1] != 3 {
				t.Fatal("kind first/node marker or slot differs")
			}
			if v.Name == "two-tier" && (got.Codes[2] != 5 || got.Codes[3] != 9) {
				t.Fatal("tier kinds differ")
			}
		})
	}
}
func FuzzSemanticClass(f *testing.F) {
	f.Add([]byte("LVMXCK02"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = Load(data, Digest(data)) })
}
