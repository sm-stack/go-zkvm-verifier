// CREDIT: https://github.com/succinctlabs/flock, MIT OR Apache-2.0.
// Equality helpers derived from pinned leanVM flock/PCS/recursion code; see NOTICE.
package field

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
	out := make([]Element, 1, 1<<uint(len(point)))
	out[0] = One
	for _, x := range point {
		n := len(out)
		out = out[:n*2]
		for i := 0; i < n; i++ {
			hi := out[i].Mul(x)
			out[n+i] = hi
			out[i] = out[i].Add(hi)
		}
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
