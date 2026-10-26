package wire

import (
	"encoding/hex"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"testing"
)

func TestRustWire(t *testing.T) {
	var v struct {
		Pin    string `json:"upstream_commit"`
		Claims []struct {
			Bytes, Digest string
			Checks        []struct {
				Claims, Groups uint64
				Accept         bool
			}
		}
		Roots []struct {
			Bytes  string
			Accept bool
		}
	}
	fixture.JSON(t, "../../testdata/wire.json", &v)
	if v.Pin != "3e7da4e783dad4c39115e5a231849e52cae5b22f" {
		t.Fatal("stale pin")
	}
	for i, c := range v.Claims {
		data := fixture.Hex(t, c.Bytes)
		claims, e := DecodeClaims(data)
		if e != nil {
			t.Fatal(e)
		}
		digest := claims.Digest()
		if hex.EncodeToString(digest[:]) != c.Digest {
			t.Fatalf("Rust claim digest %d differs", i)
		}
		for _, check := range c.Checks {
			if (claims.Check(check.Claims, check.Groups) == nil) != check.Accept {
				t.Fatalf("claim check %d differs", i)
			}
		}
		for j := 0; j < len(data); j++ {
			if _, e = DecodeClaims(data[:j]); e == nil {
				t.Fatalf("claim truncation %d/%d accepted", i, j)
			}
		}
		if _, e = DecodeClaims(append(data, 0)); e == nil {
			t.Fatal("claim trailing byte accepted")
		}
	}
	for i, c := range v.Roots {
		data := fixture.Hex(t, c.Bytes)
		r, e := DecodeRoot(data)
		if (e == nil) != c.Accept {
			t.Fatalf("root %d differs: %v", i, e)
		}
		if e != nil {
			continue
		}
		if len(r.Instance()) != 40 {
			t.Fatal("wrong instance encoding size")
		}
		for j := 0; j < len(data); j++ {
			if _, e = DecodeRoot(data[:j]); e == nil {
				t.Fatalf("root truncation %d/%d accepted", i, j)
			}
		}
		if _, e = DecodeRoot(append(data, 0)); e == nil {
			t.Fatal("root trailing byte accepted")
		}
	}
}
func FuzzWire(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte("LVMT\x14\x00"))
	f.Add([]byte{255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, b []byte) {
		if c, e := DecodeClaims(b); e == nil {
			_ = c.Digest()
			_ = c.Check(100, 100)
		}
		if r, e := DecodeRoot(b); e == nil {
			_ = r.Instance()
		}
	})
}
