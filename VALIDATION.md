# Testing and reference checks

Run from the repository root with Go 1.26+ and Python 3.9+:

```sh
CGO_ENABLED=0 GOMAXPROCS=2 go test -p 1 ./...
CGO_ENABLED=0 GOMAXPROCS=2 go test -tags purego -p 1 ./...
CGO_ENABLED=0 GOMAXPROCS=2 go build -p 1 ./...
GOMAXPROCS=2 go vet -p 1 ./...
CGO_ENABLED=1 GOMAXPROCS=2 go test -race -p 1 ./...
python3 tools/check_artifacts.py
python3 tools/gen_poseidon2.py --check
python3 tools/check_guards.py
```

Race instrumentation requires CGO; library and CLI builds do not.
On arm64, `GODEBUG=cpu.pmull=off go test ./leanvm` exercises CPU fallback.

## Coverage

| Area | Checks |
| --- | --- |
| leanVM | Rust ELF verdicts/program digests; valid execution proofs; changed ELF/output/proof; malformed lengths, truncation and trailing bytes |
| SP1 | Rust primitive/constraint vectors, compressed proof mutations and statements; key/public-value binding and encoding policy |
| Arithmetic | Bit-serial carry-less products; hardware/software fields; scalar/generated Poseidon2; boundary values and fuzz comparisons |
| ELF and bytecode | Ordered symbol lookup with overlapping tables; segment bounds/overlap; streaming slots, digests and evaluations against a materialized reference |
| Concurrency | Shared verifier/cache use; deterministic SP1 worker errors; race instrumentation |
| CLI | Acceptance/rejection/usage exit codes, bounded reads, oversized inputs, help and output failures |

All fixtures are required; missing files fail tests. The independent symbol
reference decodes records directly without the production reader or interval
cache. The bytecode reference materializes a slot-major table to check streaming
ordering, padding and multilinear evaluation. Rust vectors separately check
upstream behavior. SP1's full positive fixture commits public values with SHA-256;
BLAKE3 selection has unit coverage but no full positive proof fixture.

## Rust reference regeneration

```sh
python3 tools/regenerate.py --check
```

This uses locked dependencies and two build workers. It verifies existing proofs
and compares generated verdicts, digests and constraints; it does not generate
new execution proofs. The overlapping-symbol ELF regression is part of the
leanVM corpus and replays in ordinary Go tests. See [UPSTREAM.md](UPSTREAM.md)
for pins, encoding policy and generator provenance.

The validation tools cover distinct boundaries: artifact hashes detect file
changes; generators compare against pinned sources; guard mutations check that
negative tests fail when a selected rejection check is disabled.

## Fuzzing

Run one target at a time, for example:

```sh
CGO_ENABLED=0 GOMAXPROCS=2 go test ./leanvm -run '^$' -fuzz '^FuzzVerify$' -fuzztime 30s -parallel 1
CGO_ENABLED=0 GOMAXPROCS=2 go test ./sp1 -run '^$' -fuzz '^FuzzVerify$' -fuzztime 30s -parallel 1
```

Additional targets cover decoders, arithmetic and permutation equivalence.
Performance measurements and benchmark commands are in [PERFORMANCE.md](PERFORMANCE.md).
Security assumptions are in [README.md](README.md#security-assumptions-and-limits).
