package gf2

import (
	"encoding/binary"
	"math/rand/v2"
	"slices"
	"testing"
)

// Bit-serial base multiplication is independent of both carry-less backends.
func serialMul(a, b uint64) uint64 {
	var out uint64
	for range 64 {
		if b&1 != 0 {
			out ^= a
		}
		b >>= 1
		high := a >> 63
		a <<= 1
		if high != 0 {
			a ^= 0x1b
		}
	}
	return out
}
func serialExt(a, b Element) Element {
	var c [5]uint64
	aa, bb := [3]uint64{a.C0, a.C1, a.C2}, [3]uint64{b.C0, b.C1, b.C2}
	for i := range aa {
		for j := range bb {
			c[i+j] ^= serialMul(aa[i], bb[j])
		}
	}
	return Element{c[0] ^ c[3], c[1] ^ c[3] ^ c[4], c[2] ^ c[4]}
}
func checkKernels(t testing.TB, n int, seed uint64) {
	t.Helper()
	r := rand.New(rand.NewPCG(seed, seed+1))
	e := func() Element { return Element{r.Uint64(), r.Uint64(), r.Uint64()} }
	eq := make([]Element, n)
	raw := make([]byte, 8*n+2)
	words := raw[1 : 1+8*n] // unaligned input
	var want Element
	for i := range eq {
		eq[i] = e()
		w := r.Uint64()
		binary.LittleEndian.PutUint64(words[8*i:], w)
		want = want.Add(Element{serialMul(eq[i].C0, w), serialMul(eq[i].C1, w), serialMul(eq[i].C2, w)})
	}
	if got := DotBase(eq, words); got != want {
		t.Fatalf("dot n=%d: %v != %v", n, got, want)
	}
	table := make([]Element, 2*n+2)
	table[0] = e()
	table[len(table)-1] = e()
	before := slices.Clone(table)
	copy(table[1:], eq)
	x := e()
	EqExpand(table[1:len(table)-1], n, x)
	if table[0] != before[0] || table[len(table)-1] != before[len(table)-1] {
		t.Fatal("canary overwritten")
	}
	for i := range n {
		hi := serialExt(eq[i], x)
		if table[1+i] != eq[i].Add(hi) || table[1+n+i] != hi {
			t.Fatalf("expand n=%d row=%d", n, i)
		}
	}
}
func TestBatchKernels(t *testing.T) {
	for _, n := range []int{0, 1, 2, 31, 4095, 4096, 4097, 8193} {
		checkKernels(t, n, uint64(n))
	}
}
func TestBatchKernelBounds(t *testing.T) {
	for _, f := range []func(){func() { DotBase(make([]Element, 1), make([]byte, 7)) }, func() { EqExpand(nil, -1, One) }, func() { EqExpand(make([]Element, 3), 2, One) }, func() { EqExpand(nil, int(^uint(0)>>1), One) }} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("invalid length accepted")
				}
			}()
			f()
		}()
	}
}
func FuzzBatchKernels(f *testing.F) {
	f.Add(uint16(17), uint64(0))
	f.Add(uint16(4097), ^uint64(0))
	f.Fuzz(func(t *testing.T, n uint16, seed uint64) { checkKernels(t, int(n)%8200, seed) })
}

func TestBatchKernelFieldEdges(t *testing.T) {
	for _, v := range []uint64{0, 1, 1 << 63, ^uint64(0)} {
		a := Element{v, v, v}
		words := make([]byte, 8)
		binary.LittleEndian.PutUint64(words, v)
		want := Element{serialMul(v, v), serialMul(v, v), serialMul(v, v)}
		if DotBase([]Element{a}, words) != want {
			t.Fatal("dot edge", v)
		}
		for _, x := range []Element{{}, One, a} {
			table := []Element{a, {}}
			EqExpand(table, 1, x)
			hi := serialExt(a, x)
			if table[0] != a.Add(hi) || table[1] != hi {
				t.Fatal("expand edge", v, x)
			}
		}
	}
}
