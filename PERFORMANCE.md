# Performance

Measured 2026-10-25 on Apple M4 Pro, macOS arm64, Go 1.26.10.
All rows use `CGO_ENABLED=0`, `GOMAXPROCS=1`, five sequential batches of
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

Production class at `59c25cccfd5742f8216f259f9dd4d80d9a5f66e5`: 60,027,800 key bytes, two leaf classes, capacity 4097, 357 claims in four groups, large-tier root. Same host as above. Rust and Go ran sequentially with one worker each; five process invocations, 100 warmed verification iterations each. Values below are medians; class loading is cold once per process and includes Go's lazy circuit metadata initialization. File I/O is excluded from times.

| Operation | Go | Rust |
| --- | ---: | ---: |
| Checked class load | 121.926 ms | 97.673 ms |
| Sealed root verification | 29.739 ms | 5.412 ms |
| Direct root verification | not exposed | 18.212 ms |

Go sealed verification allocated 18,465,008 bytes and 3,711 objects per operation. Its batch means ranged from 29.693 to 29.825 ms, versus Rust's 5.385 to 5.480 ms. Go was about 5.5 times slower on this fixture. These are finite local measurements, not a general performance bound. The Go API decodes root/seal bytes on each call; the Rust tool verifies already-decoded objects. Claim decoding is outside both loops.

A separate load-only process took 122.968 ms, allocated 75,707,016 Go heap bytes during construction, and ended with 76,603,392 heap-in-use bytes. `/usr/bin/time -l` measured a **129,794,048-byte peak process RSS**. RSS includes the input key, runtime and metadata; it is not an isolated constructor allocation count. The constructor copies its key, and the input can subsequently be released.

Reproduce using an uncommitted output directory:

```sh
python3 tools/leanvm-mixed/generate_production.py /tmp/claim-production
CGO_ENABLED=0 go build -o /tmp/benchmark-claims ./tools/benchmark-claims
cargo build --locked --release -j 2 --manifest-path tools/leanvm-mixed/Cargo.toml --bin benchmark
# Run sequentially, five times each:
GOMAXPROCS=1 /tmp/benchmark-claims -dir /tmp/claim-production/two-class -n 100
tools/leanvm-mixed/target/release/benchmark /tmp/claim-production/two-class
# macOS peak process RSS for class loading:
GOMAXPROCS=1 /usr/bin/time -l /tmp/benchmark-claims -mode load -dir /tmp/claim-production/two-class
```

Generation uses two workers and omits the example's independent common-class comparison; the benchmark tools use one worker. The original example's printed verification samples are not used for the table. To benchmark the committed small corpus:

```sh
CGO_ENABLED=0 GOMAXPROCS=1 go test -p 1 ./experimental/leanvmclaims \
  -run '^$' -bench 'Benchmark(ClassLoad|VerifySealed)$' -benchmem -benchtime=20x -count=5
```
