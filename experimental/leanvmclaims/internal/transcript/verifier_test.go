package transcript

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
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

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func loadVectors(t *testing.T) vectors {
	t.Helper()
	b, e := os.ReadFile("../../testdata/transcript.json")
	if e != nil {
		t.Fatal(e)
	}
	var v vectors
	if e = json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	if v.Pin != "da5c964831c993b011464e4fd4a573b7172d5295" {
		t.Fatal("stale upstream pin")
	}
	return v
}
func TestRustTranscript(t *testing.T) {
	v := loadVectors(t)
	session := Session([]byte("leanvm/mixed-tree-seal/v2"), unhex(t, v.Relation))
	if hex.EncodeToString(session[:]) != v.Session {
		t.Fatal("Rust session mismatch")
	}
	proof, e := Decode(unhex(t, v.Proof))
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
		_, e := Decode(unhex(t, c.Bytes))
		if (e == nil) != c.Accept {
			t.Fatalf("Rust framing case %d differs: %v", i, e)
		}
	}
	for i, c := range v.Duplex {
		var iv [32]byte
		copy(iv[:], unhex(t, v.Relation))
		d := New(iv)
		d.Absorb(unhex(t, c.Input))
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
