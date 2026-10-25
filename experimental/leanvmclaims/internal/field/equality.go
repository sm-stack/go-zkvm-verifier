// CREDIT: https://github.com/succinctlabs/flock, MIT OR Apache-2.0.
// Equality helpers derived from pinned leanVM flock/PCS/recursion code; see NOTICE.
package field

import "github.com/sm-stack/go-zkvm-verifier/internal/gf2"

// EqBits evaluates the equality polynomial at a Boolean index, low bit first.
func EqBits(index uint64, point []Element) Element {
	out := One
	for i, x := range point {
		if index>>uint(i)&1 == 0 {
			x = x.Add(One)
		}
		out = out.Mul(x)
	}
	return out
}

// EqTable evaluates every Boolean index; callers bound the point dimension.
func EqTable(point []Element) []Element {
	return EqTableInto(make([]Element, 1<<uint(len(point))), point)
}

// EqTableInto initializes exactly 2^len(point) entries of caller-owned scratch.
func EqTableInto(dst []Element, point []Element) []Element {
	out := dst[: 1 : 1<<uint(len(point))]
	out[0] = One
	for _, x := range point {
		n := len(out)
		out = out[:n*2]
		gf2.EqExpand(out, n, x)
	}
	return out
}

// Eq evaluates equality over characteristic two. The points must have equal lengths.
func Eq(a, b []Element) Element {
	out := One
	for i, x := range a {
		out = out.Mul(One.Add(x).Add(b[i]))
	}
	return out
}
