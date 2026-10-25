//go:build arm64 && !purego

package gf2

import "golang.org/x/sys/cpu"

// PMULL is optional on arm64. Keep the dispatch outside the assembly so CPUs
// without it never execute an unsupported instruction. GODEBUG=cpu.pmull=off
// can exercise the fallback; -tags purego excludes this package's assembly.
var hasPMULL = cpu.ARM64.HasPMULL

func Mul64(a, b uint64) uint64 {
	if hasPMULL {
		return kmulPMULL(a, b)
	}
	return Mul64Software(a, b)
}
func Mul192(a, b Element) Element {
	if hasPMULL {
		c0, c1, c2 := extMulPMULL(a.C0, a.C1, a.C2, b.C0, b.C1, b.C2)
		return Element{c0, c1, c2}
	}
	return Mul192Software(a, b)
}

//go:noescape
func kmulPMULL(a, b uint64) uint64

//go:noescape
func extMulPMULL(a0, a1, a2, b0, b1, b2 uint64) (c0, c1, c2 uint64)

// DotBase returns the sum of eq[i] * w_i, w_i the i-th little-endian word of words.
func DotBase(eq []Element, words []byte) Element {
	if len(eq) > len(words)/8 {
		panic("gf2: DotBase words too short")
	}
	if !hasPMULL || len(eq) == 0 {
		return dotBaseSoftware(eq, words)
	}
	var out Element
	// Bounded chunks keep each assembly call short.
	for start := 0; start < len(eq); start += 4096 {
		n := min(len(eq)-start, 4096)
		c0, c1, c2 := dotBasePMULL(&eq[start], &words[8*start], n)
		out = out.Add(Element{c0, c1, c2})
	}
	return out
}

//go:noescape
func dotBasePMULL(eq *Element, words *byte, n int) (c0, c1, c2 uint64)

// EqExpand doubles an equality table in place: t[n+i] = t[i]*x, t[i] += t[n+i].
func EqExpand(t []Element, n int, x Element) {
	if n < 0 || n > len(t)/2 {
		panic("gf2: EqExpand table too short")
	}
	if !hasPMULL || n == 0 {
		eqExpandSoftware(t, n, x)
		return
	}
	for start := 0; start < n; start += 4096 {
		m := min(n-start, 4096)
		// Chunks keep the high half at the same stride n.
		eqExpandChunk(t[start:], n, m, x)
	}
}

func eqExpandChunk(t []Element, n, m int, x Element) {
	// eqExpandStrided assumes the high half starts n elements later and processes m elements.
	eqExpandStrided(&t[0], &t[n], m, x)
}

//go:noescape
func eqExpandStrided(lo, hi *Element, n int, x Element)
