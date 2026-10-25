// Benchmark the pinned claim-tree API on raw Rust-generated artifacts.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

func main() {
	dir := flag.String("dir", "", "Rust artifact directory")
	mode := flag.String("mode", "verify", "load or verify")
	n := flag.Int("n", 100, "verification iterations")
	flag.Parse()
	if *dir == "" || (*mode != "load" && *mode != "verify") || *n < 1 {
		flag.Usage()
		os.Exit(2)
	}
	read := func(name string) []byte { b, e := os.ReadFile(filepath.Join(*dir, name)); must(e); return b }
	key := read("class-key.bin")
	p, e := hex.DecodeString(string(read("class-key.digest")))
	must(e)
	if len(p) != 32 {
		must(fmt.Errorf("digest length"))
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	v, e := leanvmclaims.NewClassVerifier(key, [32]byte(p))
	must(e)
	load := time.Since(start)
	runtime.ReadMemStats(&after)
	result := map[string]any{"upstream_commit": leanvmclaims.UpstreamCommit, "class_key_bytes": len(key), "load_ns": load.Nanoseconds(), "load_allocated_bytes": after.TotalAlloc - before.TotalAlloc, "load_heap_inuse": after.HeapInuse, "workers": runtime.GOMAXPROCS(0)}
	if *mode == "verify" {
		root, seal := read("root.bin"), read("seal.bin")
		claims, e := v.DecodeClaims(read("claims.bin"))
		must(e)
		count := 0
		for _, g := range claims {
			count += len(g.Members)
		}
		must(v.VerifySealed(claims, root, seal))
		runtime.GC()
		runtime.ReadMemStats(&before)
		start = time.Now()
		for range *n {
			must(v.VerifySealed(claims, root, seal))
		}
		elapsed := time.Since(start)
		runtime.ReadMemStats(&after)
		result["claims"] = count
		result["iterations"] = *n
		result["sealed_ns"] = elapsed.Nanoseconds() / int64(*n)
		result["bytes_per_op"] = (after.TotalAlloc - before.TotalAlloc) / uint64(*n)
		result["allocs_per_op"] = (after.Mallocs - before.Mallocs) / uint64(*n)
	}
	runtime.KeepAlive(v)
	must(json.NewEncoder(os.Stdout).Encode(result))
}
func must(e error) {
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
