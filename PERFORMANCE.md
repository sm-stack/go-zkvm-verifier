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

Measured on the same host, with one worker per implementation. Each number is
the median of three sequential process runs, 100 warmed verifications per run.
Rust and Go were alternated on identical input bytes. The baseline is commit
`399813f`; current Go uses batched field kernels and reusable equality scratch.

| Fixture | Baseline Go | Current Go | Rust | Current Go / Rust |
| --- | ---: | ---: | ---: | ---: |
| Optimism operational class, 6 claims | 18.877 ms | 9.761 ms | 3.947 ms | 2.47× |
| Fork example, 357 claims | 29.812 ms | 11.516 ms | 5.435 ms | 2.12× |

Both use leanVM `59c25cccfd5742f8216f259f9dd4d80d9a5f66e5` and a
60,027,800-byte key, but different authenticated class configurations. The
operational key digest is `b20ff9b907b2320fb8139f2753172235ae2e0a66fbad11c4a55500dfb4d33b50`;
the fork example starts `05860eb9`. The operational fixture is shipped in
`experimental/leanvmclaims/testdata/production` and includes program executions
and signatures. It is not a full-capacity stress benchmark.

Operational-class verification allocated 8,108,248 bytes / 3,564 objects per
operation, versus 13,244,632 bytes / 3,568 objects at baseline. The 357-claim
fixture allocated 8,167,664 bytes / 3,706 objects, versus 18,465,008 bytes / 3,711
objects. Equality scratch retains at most one 24 MiB buffer across calls;
concurrent calls own separate scratch. Retained memory is not included in
per-operation allocated bytes.

Operational-class cold loading took 121.738 ms in Go and 99.353 ms in Rust.
Go allocated about 75.7 MB during loading, including its defensive key copy and
lazy circuit metadata initialization. This work does not optimize class loading.
The Go verification loop decodes root/seal bytes each time; Rust verifies decoded
objects. Claim decoding and file I/O are outside both loops.

Reproduce without generating any new proof:

```sh
cargo run --locked --release -j 2 --manifest-path tools/leanvm-mixed/Cargo.toml --bin production_key -- /tmp/claims-production
python3 tools/leanvm-mixed/production_fixture.py /tmp/claims-production --check
CGO_ENABLED=0 go build -o /tmp/benchmark-claims ./tools/benchmark-claims
cargo build --locked --release -j 2 --manifest-path tools/leanvm-mixed/Cargo.toml --bin benchmark
# Run sequentially, three times each:
GOMAXPROCS=1 /tmp/benchmark-claims -dir /tmp/claims-production -n 100
tools/leanvm-mixed/target/release/benchmark /tmp/claims-production
```

For the fork example, `generate_production.py OUT` generates its separate class
and proofs with two workers; benchmark `OUT/two-class` with the same commands.
The committed small corpus has Go benchmarks as well:

```sh
CGO_ENABLED=0 GOMAXPROCS=1 go test -p 1 ./experimental/leanvmclaims \
  -run '^$' -bench 'Benchmark(ClassLoad|VerifySealed)$' -benchmem -benchtime=20x -count=3
```
