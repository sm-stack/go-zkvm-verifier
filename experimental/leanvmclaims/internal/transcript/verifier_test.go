package transcript

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"golang.org/x/crypto/blake2s"
	"math/bits"
	"testing"
)

type vectors struct {
	Pin                      string `json:"upstream_commit"`
	Relation, Session, Proof string
	Challenges               []string
	Duplex                   []struct{ Input, First, Second string }
	Framing                  []struct {
		Bytes  string
		Accept bool
	}
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	var v vectors
	fixture.JSON(t, "../../testdata/transcript.json", &v)
	if v.Pin != "59c25cccfd5742f8216f259f9dd4d80d9a5f66e5" {
		t.Fatal("stale upstream pin")
	}
	return v
}
func TestRustTranscript(t *testing.T) {
	v := loadVectors(t)
	session := Session([]byte("leanvm/mixed-tree-seal/v2"), fixture.Hex(t, v.Relation))
	if hex.EncodeToString(session[:]) != v.Session {
		t.Fatal("Rust session mismatch")
	}
	proof, e := Decode(fixture.Hex(t, v.Proof))
	if e != nil {
		t.Fatal(e)
	}
	var instance [8]byte
	binary.LittleEndian.PutUint64(instance[:], 7)
	verifier, e := NewVerifier(session, instance[:], proof)
	if e != nil {
		t.Fatal(e)
	}
	var public [24]byte
	for i := range public {
		public[i] = 1
	}
	verifier.Public(public[:])
	first, e := verifier.Read(32)
	if e != nil {
		t.Fatal(e)
	}
	for _, b := range first {
		if b != 5 {
			t.Fatal("wrong first message")
		}
	}
	check := func(index int) {
		var challenge [24]byte
		if e := verifier.Draw(challenge[:]); e != nil {
			t.Fatal(e)
		}
		if hex.EncodeToString(challenge[:]) != v.Challenges[index] {
			t.Fatalf("Rust challenge %d differs", index)
		}
	}
	check(0)
	if _, e = verifier.Read(24); e != nil {
		t.Fatal(e)
	}
	hint, e := verifier.Hint()
	if e != nil || string(hint) != "opening" {
		t.Fatalf("hint: %q %v", hint, e)
	}
	if e = verifier.CheckPOW(8); e != nil {
		t.Fatal(e)
	}
	check(1)
	if e = verifier.CheckPOW(0); e != nil {
		t.Fatal(e)
	}
	check(2)
	if e = verifier.EOF(); e != nil {
		t.Fatal(e)
	}
	for i, c := range v.Framing {
		_, e := Decode(fixture.Hex(t, c.Bytes))
		if (e == nil) != c.Accept {
			t.Fatalf("Rust framing case %d differs: %v", i, e)
		}
	}
	for i, c := range v.Duplex {
		var iv [32]byte
		copy(iv[:], fixture.Hex(t, v.Relation))
		d := New(iv)
		d.Absorb(fixture.Hex(t, c.Input))
		for j, want := range []string{c.First, c.Second} {
			if j == 1 {
				d.Absorb([]byte("next"))
			}
			got := make([]byte, len(want)/2)
			if e = d.Squeeze(got); e != nil {
				t.Fatal(e)
			}
			if hex.EncodeToString(got) != want {
				t.Fatalf("duplex case %d run %d differs", i, j)
			}
		}
	}
}
func TestPoisonAndEOF(t *testing.T) {
	v, e := NewVerifier([32]byte{}, []byte{1}, Proof{})
	if e != nil {
		t.Fatal(e)
	}
	_, first := v.Read(24)
	if first == nil {
		t.Fatal("missing read accepted")
	}
	if _, e = v.Hint(); e != first {
		t.Fatal("hint lost poison")
	}
	if e = v.EOF(); e != first {
		t.Fatal("EOF lost poison")
	}
	if _, e = NewVerifier([32]byte{}, nil, Proof{}); e == nil {
		t.Fatal("empty instance accepted")
	}
	for _, p := range []Proof{{Messages: []byte{1}}, {Hints: []byte{0, 0, 0, 0}}} {
		v, e = NewVerifier([32]byte{}, []byte{1}, p)
		if e != nil {
			t.Fatal(e)
		}
		if v.EOF() == nil {
			t.Fatal("unread bytes accepted")
		}
	}
}
func FuzzDecode(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{255, 255, 255, 255, 255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, data []byte) {
		p, e := Decode(data)
		if e != nil {
			return
		}
		v, e := NewVerifier([32]byte{}, []byte{1}, p)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = v.Read(len(p.Messages)); e != nil {
			t.Fatal(e)
		}
		for len(v.hints) > 0 {
			if _, e = v.Hint(); e != nil {
				t.Fatal(e)
			}
		}
		if e = v.EOF(); e != nil {
			t.Fatal(e)
		}
	})
}

func TestPOWBinding(t *testing.T) {
	// Select both a valid and invalid nonce using a separate hash calculation.
	const difficulty = 8
	var iv [32]byte
	d := New(iv)
	d.Absorb([]byte{1})
	var block [64]byte
	if err := d.Squeeze(block[:32]); err != nil {
		t.Fatal(err)
	}
	copy(block[56:], "FS-POW-1")
	found := [2]bool{}
	for nonce := uint64(0); !found[0] || !found[1]; nonce++ {
		binary.LittleEndian.PutUint64(block[32:40], nonce)
		hash := blake2s.Sum256(block[:])
		valid := bits.LeadingZeros64(binary.LittleEndian.Uint64(hash[:8])) >= difficulty
		index := 0
		if valid {
			index = 1
		}
		if found[index] {
			continue
		}
		found[index] = true
		v, err := NewVerifier(iv, []byte{1}, Proof{Messages: append([]byte(nil), block[32:40]...)})
		if err != nil {
			t.Fatal(err)
		}
		err = v.CheckPOW(difficulty)
		if valid {
			if err != nil || v.EOF() != nil {
				t.Fatalf("valid nonce: %v", err)
			}
		} else {
			if !errors.Is(err, ErrPOW) || !errors.Is(v.EOF(), ErrPOW) {
				t.Fatalf("invalid nonce: %v", err)
			}
		}
	}
}
