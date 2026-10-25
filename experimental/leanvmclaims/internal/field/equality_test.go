package field

import "testing"

func TestEqualityTableOrder(t *testing.T) {
	for _, n := range []int{0, 1, 2, 8, 14} {
		point := make([]Element, n)
		for i := range point {
			point[i] = Element{C0: uint64(i + 3), C1: uint64(i*7 + 11), C2: uint64(i * 13)}
		}
		for i, v := range EqTable(point) {
			if v != EqBits(uint64(i), point) {
				t.Fatalf("dimension %d index %d", n, i)
			}
		}
	}
}
