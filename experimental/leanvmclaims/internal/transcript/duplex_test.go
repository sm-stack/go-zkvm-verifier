package transcript

import (
	"encoding/hex"
	"testing"
)

func TestUpstreamKnownAnswer(t *testing.T) {
	// crates/fiat_shamir/src/duplex.rs::a_known_answer_pins_the_mode at the pinned commit.
	var iv [32]byte
	for i := range iv {
		iv[i] = byte(i)
	}
	input := make([]byte, 131)
	for i := range input {
		input[i] = byte(i)
	}
	want := "72d518bf9786c4060f03f3cb68a3ffc32dda36374ed40d4bb910659749d061d422f71eefc6691565f8a51fa46683db43"
	for chunk := 1; chunk <= 140; chunk++ {
		d := New(iv)
		for at := 0; at < len(input); at += chunk {
			d.Absorb(input[at:min(at+chunk, len(input))])
			if err := d.Squeeze(nil); err != nil {
				t.Fatal(err)
			}
		}
		out := make([]byte, 48)
		for at := 0; at < 40; at += chunk {
			d.Absorb(nil)
			if err := d.Squeeze(out[at:min(at+chunk, 40)]); err != nil {
				t.Fatal(err)
			}
		}
		d.Absorb([]byte("a"))
		d.Absorb([]byte("b"))
		if err := d.Squeeze(out[40:]); err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(out) != want {
			t.Fatalf("chunk %d: %x", chunk, out)
		}
	}
}

func TestSqueezeOverflowAtomic(t *testing.T) {
	d := New([32]byte{})
	d.Absorb([]byte("pending"))
	d.squeezed = maxSqueeze - 1
	before := d
	out := [2]byte{7, 8}
	if d.Squeeze(out[:]) == nil || d != before || out != [2]byte{7, 8} {
		t.Fatal("overflow changed state or output")
	}
}

func FuzzDuplexStreaming(f *testing.F) {
	f.Add([]byte("hello"), uint8(3), uint8(33))
	f.Fuzz(func(t *testing.T, input []byte, chunkByte, outByte uint8) {
		chunk := int(chunkByte) + 1
		n := int(outByte) + 1
		a, b := New([32]byte{}), New([32]byte{})
		a.Absorb(input)
		for at := 0; at < len(input); at += chunk {
			b.Absorb(input[at:min(at+chunk, len(input))])
		}
		x, y := make([]byte, n), make([]byte, n)
		if err := a.Squeeze(x); err != nil {
			t.Fatal(err)
		}
		for at := 0; at < n; at += chunk {
			if err := b.Squeeze(y[at:min(at+chunk, n)]); err != nil {
				t.Fatal(err)
			}
		}
		if string(x) != string(y) {
			t.Fatal("stream split changed challenge")
		}
		a.Absorb([]byte{1})
		b.Absorb([]byte{1})
		if err := a.Squeeze(x); err != nil {
			t.Fatal(err)
		}
		if err := b.Squeeze(y); err != nil {
			t.Fatal(err)
		}
		if string(x) != string(y) {
			t.Fatal("squeeze framing changed challenge")
		}
	})
}
