//go:build !arm64 || purego

package gf2

func Mul64(a, b uint64) uint64    { return Mul64Software(a, b) }
func Mul192(a, b Element) Element { return Mul192Software(a, b) }

func DotBase(eq []Element, words []byte) Element {
	if len(eq) > len(words)/8 {
		panic("gf2: DotBase words too short")
	}
	return dotBaseSoftware(eq, words)
}

func EqExpand(t []Element, n int, x Element) {
	if n < 0 || n > len(t)/2 {
		panic("gf2: EqExpand table too short")
	}
	eqExpandSoftware(t, n, x)
}
