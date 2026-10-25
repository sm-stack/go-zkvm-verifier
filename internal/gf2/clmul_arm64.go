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
