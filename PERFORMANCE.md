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
one worker (`GOMAXPROCS=1`; Rust pool size 1), with default release optimization
and no custom RUSTFLAGS. Values below are medians of three alternating Go/Rust
batches of 100 warmed verifications. Both verify the same serialized fixture;
loading and Go claim decoding occur outside the verification timer.

The current pin is `fc3fc9ec0ec218d6b5196ecae85a975590729ae6`. All four cases use
the same 1,288-byte operational class key with digest `5345ead0…`.

| Fixture | Members | Go | Rust | Go/Rust | Go allocated bytes/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| plain-small | 256 | 4.319 ms | 2.526 ms | 1.71× | 7,817,136 |
| plain-large | 384 | 5.249 ms | 3.016 ms | 1.74× | 8,303,112 |
| mixed-zk | 144 | 4.945 ms | 2.806 ms | 1.76× | 8,175,912 |
| one-zk | 16 | 4.928 ms | 2.798 ms | 1.76× | 8,177,720 |

Go batches ranged 4.317–4.325, 5.246–5.266, 4.939–5.206 and 4.874–4.938 ms,
respectively. Rust batches ranged 2.479–2.600, 2.996–3.119, 2.798–2.867 and
2.780–2.815 ms. These local samples are not cross-machine guarantees.

### Key loading and previous-format baseline

The baseline binary was built from Go commit `02d7ea9b25b2bfaabc388b3ad1028f01857f3e4a`
before changing the verifier. Its operational v3 fixture has seven members and
key digest `ce8d9001…`. The compact fixture uses the same class dimensions, but
different programs/member sets. Verification time is therefore **not** an
apples-to-apples speedup comparison with that baseline.

| Go measurement | Baseline | Compact key |
| --- | ---: | ---: |
| Serialized key | 116,251,536 B | 1,288 B |
| First load in a new process | 191.787 ms | 46.454–50.274 ms |
| Bytes allocated during first load | 131,953,512 B | about 15,690,600 B |
| Sealed verify | 6.629 ms (7 members) | see fixture-specific table above |

First-load allocation excludes the caller's already-read key. It includes the
one-time decoding of shared circuit metadata, which now dominates Go startup.
With that metadata initialized, repeated compact-key loads take 21–25 µs,
69,152 B/op and 106 allocations/op. Rust compact-key load samples were
0.628–0.910 ms; its descriptor adapter runs before the load timer. Neither
allocation figures nor Go's heap-in-use counter represent peak RSS.

Compact verification retains no process-wide bus scratch buffer. The deprecated
`SetScratchCacheLimit` API is a compatibility no-op.

### Reproduce

Extract one checked-in fixture into a raw artifact directory:

```sh
python3 - <<'PYTHON'
import gzip
from pathlib import Path
base = Path('experimental/leanvmclaims/testdata/compact')
out = Path('/tmp/compact-benchmark')
out.mkdir(exist_ok=True)
for name in ['class-key.bin', 'class-key.digest',
             'mixed-zk/root.bin', 'mixed-zk/claims.bin', 'mixed-zk/seal.bin']:
    (out / Path(name).name).write_bytes(gzip.decompress((base / (name+'.gz')).read_bytes()))
PYTHON
CGO_ENABLED=0 go build -o /tmp/benchmark-claims ./tools/benchmark-claims
GOMAXPROCS=1 /tmp/benchmark-claims -dir /tmp/compact-benchmark -n 100
cargo run --locked --release -j 2 --manifest-path tools/leanvm-mixed/Cargo.toml \
  --bin benchmark -- /tmp/compact-benchmark
CGO_ENABLED=0 GOMAXPROCS=1 go test -p 1 ./experimental/leanvmclaims \
  -run '^$' -bench '^BenchmarkClassLoad$' -benchmem -count 3
```

Use `plain-small`, `plain-large` or `one-zk` instead of `mixed-zk` for the other
cases. No proof generation is needed. The baseline fixture and implementation
can be recovered from the baseline git commit; old formats are not accepted by
the current verifier.
