//go:build !arm64 || purego

package leanvm

func kmul(a, b uint64) uint64 { return kmulSoftware(a, b) }
func (a ext) mul(b ext) ext   { return a.mulSoftware(b) }
