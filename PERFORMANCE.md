# Performance

Measured 2026-10-25 on Apple M4 Pro, macOS arm64, Go 1.26.10.
The standalone rows below use `CGO_ENABLED=0`, `GOMAXPROCS=1`, five sequential batches of
20 operations. Times are medians of batch means; ranges show all five batches.
Allocated bytes are per operation, not peak RSS.

| Operation / fixture | Median | Batch range | Bytes/op | Allocs/op |
| --- | ---: | ---: | ---: | ---: |
| leanVM Fibonacci n=1000 | 4.508 ms | 4.408–5.094 ms | 4,171,544 | 4,072 |
| leanVM preimage, 40,000 bytes | 4.363 ms | 4.314–4.497 ms | 3,928,568 | 3,522 |
| SP1 Fibonacci n=1000000 | 25.134 ms | 24.849–26.835 ms | 2,017,133 | 1,476 |

Fixture loading and decompression are excluded. Each verification decodes its
proof; leanVM also loads the ELF and computes its program digest. Circuit
metadata is warm. Rust was not remeasured with this table, so no Go/Rust ratio
is reported.

## Runtime backends

- Both leanVM verifiers use shared arm64 PMULL when supported, with runtime CPU detection. `purego`
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

## Experimental claim trees

Measured 2026-10-26 on Apple M4 Pro, macOS arm64, Go 1.26.10 and
Rust 1.99.1. Both verifiers use leanVM
`3e269bd4137976648052a3335845d0c19693ec0d`. Rust uses the default release profile;
Go uses `CGO_ENABLED=0`, `GOMAXPROCS=1`. Each implementation uses one worker.
Three sequential runs alternate Go and Rust on identical input bytes, with
100 warmed verifications per run. Values are medians of those batch means.

| Operational fixture | Key bytes | Claims | Go verify | Rust verify | Go / Rust |
| --- | ---: | ---: | ---: | ---: | ---: |
| v2, `5926b5cf…` | 92,550,040 | 6 | 6.022 ms | 3.949 ms | 1.52× |
| v3, `ce8d9001…` | 116,251,536 | 7 | 6.780 ms | 4.333 ms | 1.56× |

| Operational fixture | Go load | Rust load | Go load allocated | Go verify bytes/op | Allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| v2 | 160.923 ms | 147.059 ms | 108,229,736 B | 8,137,176 | 3,574 |
| v3 | 189.816 ms | 188.146 ms | 131,953,672 B | 8,542,640 | 4,596 |

These are different aggregates: v3 adds a private-program claim, a dedicated
ZK tier and a LeafWrap. Its seal is 523,172 bytes versus 346,936 for v2. The
comparison does not isolate the cost of ZK or measure full-capacity operation.
Shared-host interference was visible: Go batches ranged 5.873–6.048 ms (v2)
and 6.549–9.777 ms (v3); Rust ranged 3.935–13.482 ms and 4.294–4.336 ms.

Go decodes the root/seal on every call; Rust times already-decoded objects.
Claim decoding, file reads and fixture decompression are outside both loops.
Load allocation includes the Go key copy and lazy circuit metadata; it is
allocated bytes, not peak RSS. Verification retains the default one-buffer
scratch cache, capped at 24 MiB. `SetScratchCacheLimit(0)` releases and disables
that cache; the limit does not cap active allocations or loaded class keys.

Reproduce directly from the shipped fixtures:

```sh
CGO_ENABLED=0 GOMAXPROCS=1 go test -p 1 ./experimental/leanvmclaims \
  -run '^$' -bench '^BenchmarkOperationalZK$' -benchmem -count=3
```

For paired Rust/Go process measurements, decompress each operational fixture's
`class-key.bin.gz`, `class-key.digest.gz` and `production/{root,claims,seal}.bin.gz`
into one directory, then run:

```sh
CGO_ENABLED=0 go build -o /tmp/benchmark-claims ./tools/benchmark-claims
GOMAXPROCS=1 /tmp/benchmark-claims -dir /tmp/operational-v3 -n 100
cargo run --locked --release -j 2 --manifest-path tools/leanvm-zk/Cargo.toml \
  --bin benchmark -- /tmp/operational-v3
```

The fixture provenance and source snapshots are described in
[the ZK reference tools](tools/leanvm-zk/README.md). No new leaf proving is needed
for these measurements.
