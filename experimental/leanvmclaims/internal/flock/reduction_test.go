package flock

import (
	"encoding/hex"
	"errors"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"reflect"
	"testing"

	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/machine"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
)

type resultVector struct {
	Point, Slices, Rows, Cols [][3]uint64
	Alpha, Skip, Value        [3]uint64
}
type caseVector struct {
	Shapes    []Shape
	Messages  string
	Results   []resultVector
	Mutations []struct {
		At     int
		Accept bool
	}
}

func loadVectors(t testing.TB) ([32]byte, []caseVector) {
	t.Helper()
	var v struct {
		Pin     string `json:"upstream_commit"`
		Session string
		Phi     [][3]uint64
		Cases   []caseVector
	}
	fixture.JSON(t, "../../testdata/flock.json", &v)
	if v.Pin != "59c25cccfd5742f8216f259f9dd4d80d9a5f66e5" || len(v.Cases) != 3 || len(v.Phi) != 256 {
		t.Fatal("stale or incomplete flock vectors")
	}
	for i, w := range v.Phi {
		if phi(i) != element(w) {
			t.Fatalf("phi8[%d] differs", i)
		}
	}
	b, err := hex.DecodeString(v.Session)
	if err != nil || len(b) != 32 {
		t.Fatal("bad session")
	}
	session := [32]byte(b)
	if session != transcript.Session([]byte("go-port-flock-components"), nil) {
		t.Fatal("session differs")
	}
	return session, v.Cases
}
func element(w [3]uint64) E { return E{C0: w[0], C1: w[1], C2: w[2]} }
func elements(ws [][3]uint64) []E {
	out := make([]E, len(ws))
	for i, w := range ws {
		out[i] = element(w)
	}
	return out
}
func replay(session [32]byte, messages []byte, shapes []Shape) ([]Replay, error) {
	v, err := transcript.NewVerifier(session, make([]byte, 8), transcript.Proof{Messages: messages})
	if err != nil {
		return nil, err
	}
	result, err := Verify(v, shapes)
	if err == nil {
		err = v.EOF()
	}
	return result, err
}
func TestRustReduction(t *testing.T) {
	session, cases := loadVectors(t)
	for i, c := range cases {
		messages, err := hex.DecodeString(c.Messages)
		if err != nil {
			t.Fatal(err)
		}
		got, err := replay(session, messages, c.Shapes)
		if err != nil {
			t.Fatalf("case%d: %v", i, err)
		}
		if len(got) != len(c.Results) {
			t.Fatal("wrong result count")
		}
		for j, r := range c.Results {
			want := MatrixClaim{Alpha: element(r.Alpha), Skip: element(r.Skip), Value: element(r.Value), Rows: elements(r.Rows), Cols: elements(r.Cols), Slices: elements(r.Slices)}
			if !reflect.DeepEqual(got[j].Matrix, want) || !reflect.DeepEqual(got[j].Claim.Point, elements(r.Point)) || !reflect.DeepEqual(got[j].Claim.Slices, elements(r.Slices)) {
				t.Fatalf("case %d/%d replay differs", i, j)
			}
		}
		for _, m := range c.Mutations {
			edited := append([]byte(nil), messages...)
			edited[m.At] ^= 1
			_, err := replay(session, edited, c.Shapes)
			if (err == nil) != m.Accept {
				t.Fatalf("case%d mutation%d: %v", i, m.At, err)
			}
		}
		for n := 0; n < len(messages); n += 24 {
			if _, err := replay(session, messages[:n], c.Shapes); err == nil {
				t.Fatalf("accepted cut %d", n)
			}
		}
		if _, err := replay(session, append(messages, 0), c.Shapes); err == nil {
			t.Fatal("accepted trailing byte")
		}
	}
}
func TestInterpolationNodes(t *testing.T) {
	for i := 0; i < 64; i++ {
		weights := lagrangeWeights(phi(i))
		for j, w := range weights {
			want := E{}
			if i == j {
				want = one
			}
			if w != want {
				t.Fatalf("basis %d/%d differs", i, j)
			}
		}
	}
}
func FuzzReduction(f *testing.F) {
	session, cases := loadVectors(f)
	for _, c := range cases {
		m, err := hex.DecodeString(c.Messages)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(m)
	}
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = replay(session, data, cases[0].Shapes) })
}

func TestRustMatrixClaims(t *testing.T) {
	var v struct {
		Pin      string `json:"upstream_commit"`
		Circuits []struct {
			Index  int
			Probes []struct {
				Row, Column [][3]uint64
				Alpha       [3]uint64
				Flock       struct {
					Skip, Value [3]uint64
					Slices      [][3]uint64
				}
			}
		}
	}
	fixture.JSON(t, "../../testdata/matrices.json", &v)
	s, err := machine.Load()
	if err != nil {
		t.Fatal(err)
	}
	if v.Pin != s.Pin || len(v.Circuits) != 21 {
		t.Fatal("stale matrix vectors")
	}
	for _, c := range v.Circuits {
		circuit := &s.Circuits[c.Index]
		scratch := make([]E, len(circuit.Gates))
		if len(c.Probes) != 3 {
			t.Fatal("missing matrix probes")
		}
		for _, p := range c.Probes {
			rest := circuit.KLog - 6
			m := MatrixClaim{Alpha: element(p.Alpha), Skip: element(p.Flock.Skip), Value: element(p.Flock.Value), Rows: elements(p.Row[:rest]), Cols: elements(p.Column[:rest]), Slices: elements(p.Flock.Slices)}
			if err = m.Check(circuit, scratch); err != nil {
				t.Fatalf("matrix %d: %v", c.Index, err)
			}
			m.Value = m.Value.Add(one)
			if err = m.Check(circuit, scratch); err == nil {
				t.Fatal("accepted false matrix claim")
			}
		}
	}
}

func TestZerocheckTerminalBinding(t *testing.T) {
	// Zero round polynomials leave a zero claim. The terminal (a,b,c)=(0,0,1)
	// violates a*b+c=0. No lincheck payload follows: its truncation must not be
	// mistaken for rejection by the zerocheck terminal constraint.
	shape := Shape{KLog: skipLog, Pin: 0, LogInstances: len(fixedChallenges)}
	var messages fixture.Messages
	messages.Zeros(skipSize) // Values of the skip-round polynomial.
	for range len(fixedChallenges) {
		messages.Elements(E{}, E{}) // Two transmitted quadratic coefficients.
	}
	messages.Elements(E{}, E{}, one) // Terminal a, b, c.
	v, err := transcript.NewVerifier([32]byte{}, []byte{1}, transcript.Proof{Messages: messages})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(v, []Shape{shape})
	if !errors.Is(err, ErrZerocheckTerminal) {
		t.Fatalf("wanted terminal rejection, got %v", err)
	}
}
