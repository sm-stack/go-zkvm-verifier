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

Measured on Apple M4 Pro, macOS arm64, Go 1.26.10 and Rust 1.99.1. Both use
one worker (`GOMAXPROCS=1`; Rust pool size 1), default release optimization and
no custom RUSTFLAGS. Values are medians of three sequential batches of 100
warmed verifications, alternating binaries. Loading and Go claim decoding are
outside the verification timer. Rust is pinned to
`3e7da4e783dad4c39115e5a231849e52cae5b22f`.

| Binary / fixture | Members | Key | Verify | Go allocation/op |
| --- | ---: | ---: | ---: | ---: |
| Go `32f9be6`, isolated mixed-zk | 144 | 1,288 B | 4.796 ms | 8,175,912 B |
| Current Go, same isolated fixture | 144 | 1,288 B | 4.781 ms | 8,175,912 B |
| Rust, same isolated fixture | 144 | 1,288 B | 2.730 ms | — |
| Current Go, shared fixture | 1,168 | 936 B | 3.790 ms | 7,593,256 B |
| Rust, same shared fixture | 1,168 | 936 B | 2.186 ms | — |

The isolated Go comparison shows no material regression in these samples.
The shared Go verifier is about 1.73× the Rust time. Shared and isolated fixtures
have different programs, member sets, capacity and tree rate (3 versus 1);
their difference is not a controlled measurement of placement alone.

Shared Go batches ranged 3.727–4.001 ms; Rust ranged 2.149–2.224 ms. Baseline Go
isolated batches ranged 4.786–4.828 ms and current Go 4.765–4.837 ms. Shared-host
and startup variation remain; these samples are not cross-machine guarantees.

### Loading and memory

| First load in a new process | Time range | Go allocated bytes |
| --- | ---: | ---: |
| Go `32f9be6`, isolated | 46.439–53.425 ms | about 15,690,800 |
| Current Go, isolated | 46.069–47.616 ms | about 15,690,300 |
| Current Go, shared | 46.298–47.794 ms | about 15,664,000 |
| Rust, shared | 0.529–1.531 ms | — |

First-load allocation excludes the caller's already-read key and includes the
one-time decoding of shared circuit metadata, which dominates Go startup.
After metadata initialization, repeated shared-key loads take about 12 µs,
42,952 B/op and 69 allocations/op.
Rust's descriptor adapter runs before its load timer. These figures are
allocated bytes, not peak RSS. Compact verification has no persistent bus scratch
buffer; `SetScratchCacheLimit` remains a deprecated compatibility no-op.

The shared serialized root and seal total 354,999 bytes. With the separate
38,056-byte claims encoding, the total is 393,055 bytes. Transport/blob budgeting
belongs to the embedding application; the verifier adds no transport-size cap.

### Reproduce

Extract the shared fixture into a raw artifact directory:

```sh
python3 - <<'PYTHON'
import gzip
from pathlib import Path
base = Path('experimental/leanvmclaims/testdata/shared')
out = Path('/tmp/shared-benchmark')
out.mkdir(exist_ok=True)
for name in ['class-key.bin', 'class-key.digest', 'root.bin', 'claims.bin', 'seal.bin']:
    (out / name).write_bytes(gzip.decompress((base / (name+'.gz')).read_bytes()))
PYTHON
CGO_ENABLED=0 go build -o /tmp/benchmark-claims ./tools/benchmark-claims
GOMAXPROCS=1 /tmp/benchmark-claims -dir /tmp/shared-benchmark -n 100
cargo run --locked --release -j 2 --manifest-path tools/leanvm-mixed/Cargo.toml \
  --bin benchmark -- /tmp/shared-benchmark
CGO_ENABLED=0 GOMAXPROCS=1 go test -p 1 ./experimental/leanvmclaims \
  -run '^$' -bench '^BenchmarkSharedLoad$' -benchmem -count 3
```

For the isolated comparison, use `testdata/compact`, extracting
`mixed-zk/{root,claims,seal}.bin.gz` to the raw directory alongside its key/digest.
The baseline binary can be built from git commit `32f9be6` in a separate checkout;
its verifier does not accept shared keys. No proof generation is needed.
