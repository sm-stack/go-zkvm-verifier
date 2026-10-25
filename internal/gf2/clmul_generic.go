//go:build !arm64 || purego

package gf2

func Mul64(a, b uint64) uint64    { return Mul64Software(a, b) }
func Mul192(a, b Element) Element { return Mul192Software(a, b) }
