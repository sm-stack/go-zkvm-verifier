package recursion

import (
	"sync"
	"testing"
)

func TestScratchCachePolicy(t *testing.T) {
	defer SetScratchCacheLimit(defaultScratchCacheBytes)
	if err := SetScratchCacheLimit(-1); err == nil {
		t.Fatal("negative limit")
	}
	SetScratchCacheLimit(0)
	held := takeBusScratch(8)
	releaseBusScratch(held)
	if busScratch.buffer != nil {
		t.Fatal("disabled cache retained buffer")
	}
	SetScratchCacheLimit(8 * 24)
	releaseBusScratch(held)
	reused := takeBusScratch(8)
	if &reused[0] != &held[0] {
		t.Fatal("cache did not reuse buffer")
	}
	SetScratchCacheLimit(0) // disabling while a verification owns a buffer
	releaseBusScratch(reused)
	if busScratch.buffer != nil {
		t.Fatal("in-flight return repopulated disabled cache")
	}
	SetScratchCacheLimit(7 * 24)
	releaseBusScratch(held)
	if busScratch.buffer != nil {
		t.Fatal("oversized buffer retained")
	}
}
func TestConcurrentCachePolicy(t *testing.T) {
	defer SetScratchCacheLimit(defaultScratchCacheBytes)
	var wg sync.WaitGroup
	for worker := range 4 {
		wg.Go(func() {
			for range 100 {
				if worker == 0 {
					SetScratchCacheLimit(0)
					SetScratchCacheLimit(24 * 64)
					continue
				}
				b := takeBusScratch(64)
				for i := range b {
					b[i] = E{C0: uint64(worker)}
				}
				for _, v := range b {
					if v.C0 != uint64(worker) {
						t.Error("shared active scratch")
					}
				}
				releaseBusScratch(b)
			}
		})
	}
	wg.Wait()
	SetScratchCacheLimit(0)
}
