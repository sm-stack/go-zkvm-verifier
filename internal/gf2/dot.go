package gf2

import "encoding/binary"

// dotBaseSoftware accumulates unreduced products; reduction is linear over XOR.
func dotBaseSoftware(eq []Element, words []byte) Element {
	var h0, l0, h1, l1, h2, l2 uint64
	for i, e := range eq {
		w := binary.LittleEndian.Uint64(words[8*i:])
		a, b := Clmul(e.C0, w)
		h0, l0 = h0^a, l0^b
		a, b = Clmul(e.C1, w)
		h1, l1 = h1^a, l1^b
		a, b = Clmul(e.C2, w)
		h2, l2 = h2^a, l2^b
	}
	return Element{Reduce(h0, l0), Reduce(h1, l1), Reduce(h2, l2)}
}

func eqExpandSoftware(t []Element, n int, x Element) {
	for i := 0; i < n; i++ {
		hi := Mul192Software(t[i], x)
		t[n+i] = hi
		t[i] = t[i].Add(hi)
	}
}
