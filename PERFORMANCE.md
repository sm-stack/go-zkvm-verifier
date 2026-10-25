# Performance

Measured 2026-10-25 on Apple M4 Pro, macOS arm64, Go 1.26.10.
All rows use `CGO_ENABLED=0`, `GOMAXPROCS=1`, five sequential batches of
20 operations. Times are medians of batch means; ranges show all five batches.
Allocated bytes are per operation, not peak RSS.

| Operation / fixture | Median | Batch range | Bytes/op | Allocs/op |
| --- | ---: | ---: | ---: | ---: |
| leanVM Fibonacci n=1000 | 4.455 ms | 4.413–5.103 ms | 4,185,776 | 4,323 |
| leanVM preimage, 40,000 bytes | 4.406 ms | 4.355–4.840 ms | 3,950,168 | 3,879 |
| SP1 Fibonacci n=1000000 | 25.586 ms | 24.428–26.932 ms | ~2,017,133 | 1,476 |

Fixture loading and decompression are excluded. Each verification decodes its
proof; leanVM also loads the ELF and computes its program digest. Circuit
metadata is warm. Rust was not remeasured with this table, so no Go/Rust ratio
is reported.

## Runtime backends

- leanVM uses arm64 PMULL when supported, with runtime CPU detection. `purego`
  and other architectures use the portable field implementation.
- Bytecode digesting streams slot-major words through a 4 KiB buffer. Evaluation
  uses a shared 256-element field buffer and logarithmic recursion depth.
- SP1 uses generated scalar Poseidon2 lanes with delayed reductions. With
  `GOMAXPROCS > 1`, large Merkle batches can use one additional worker; the table
  above uses the sequential path.

## Reproduction

```sh
CGO_ENABLED=0 GOMAXPROCS=1 go test -p 1 ./leanvm ./sp1 \
  -run '^$' -bench '^BenchmarkVerify' -benchmem -benchtime=20x -count=5
# Portable leanVM backend:
CGO_ENABLED=0 GOMAXPROCS=1 go test -tags purego ./leanvm \
  -run '^$' -bench '^BenchmarkVerify' -benchmem -benchtime=20x -count=5
```

Run benchmarks sequentially on an otherwise idle machine. For a direct Rust
comparison, use the same fixtures and measure both implementations in that run:

```sh
cargo build --locked --release -j 2 --manifest-path tools/leanvm/Cargo.toml --example benchmark_verify
cargo build --locked --release -j 2 --manifest-path tools/sp1/Cargo.toml --example benchmark_verify
RAYON_NUM_THREADS=1 tools/leanvm/target/release/examples/benchmark_verify
RAYON_NUM_THREADS=1 tools/leanvm/target/release/examples/benchmark_verify preimage
# DIR contains decompressed proof.bin and the public_values.bin/vkey_hash.bin
# from sp1/testdata/fixture.
RAYON_NUM_THREADS=1 tools/sp1/target/release/examples/benchmark_verify DIR
```
