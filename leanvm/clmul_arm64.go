//go:build arm64 && !purego

package leanvm

import "golang.org/x/sys/cpu"

// PMULL is optional on arm64. Keep the dispatch outside the assembly so CPUs
// without it never execute an unsupported instruction. GODEBUG=cpu.pmull=off
// can exercise the fallback; -tags purego excludes this package's assembly.
var hasPMULL = cpu.ARM64.HasPMULL

func kmul(a, b uint64) uint64 {
	if hasPMULL {
		return kmulPMULL(a, b)
	}
	return kmulSoftware(a, b)
}
func (a ext) mul(b ext) ext {
	if hasPMULL {
		c0, c1, c2 := extMulPMULL(a.c0, a.c1, a.c2, b.c0, b.c1, b.c2)
		return ext{c0, c1, c2}
	}
	return a.mulSoftware(b)
}

//go:noescape
func kmulPMULL(a, b uint64) uint64

//go:noescape
func extMulPMULL(a0, a1, a2, b0, b1, b2 uint64) (c0, c1, c2 uint64)
