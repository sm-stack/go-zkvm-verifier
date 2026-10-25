# stark-go-verify

**Verify zkVM execution proofs directly in Go.** This project lets Go services
check leanVM and SP1 proofs without running a Rust verifier, using CGO, or calling
an external verification service. It provides Go libraries and a verification CLI;
proof generation stays with the upstream zkVM tools.

The goal is to preserve the pinned Rust verifiers' decisions and program identity
checks, with reproducible test vectors for comparing the implementations.
Compatibility is defined per protocol and encoding; see [UPSTREAM.md](UPSTREAM.md).

Requires **Go 1.26+**. Module: `github.com/sm-stack/go-zkvm-verifier`.
The library and CLI need no network access at runtime.

## Supported proofs

| Package | Pinned implementation | Verification inputs |
| --- | --- | --- |
| `leanvm` | sm-stack/leanVM fork 0.1.0, `c3fc7b2a9195ed995f7f7e9f8245ad6e8a4dfb14` | RV64 guest ELF, 32 output bytes, LVMP v1 execution proof |
| `sp1` | SP1 6.8.1, `c84ada1ed5911f28c4d3c9d0ed2f9e6cd7edb824` | Program verifying-key digest, public values, bincode `SP1Proof::Compressed` |

The leanVM package targets a specific **sm-stack fork**, not upstream leanVM main.
SP1 uses KoalaBear and the pinned recursion-key tree with **mprotect disabled**.
Other versions and SP1 Core/Plonk/Groth16 proofs are outside the supported scope.
The two packages have separate APIs reflecting their different statements.

A custom claim-tree verifier lives under
[`experimental/leanvmclaims`](#experimental-extension-leanvm-claim-trees).
It has a separate protocol pin and experimental API. Proving, chain/RPC
integration, and formal verification are outside this project.

## Use the libraries

leanVM returns the verified program digest. Check both the error and the digest
against the program your application trusts:

```go
import (
    "fmt"
    "github.com/sm-stack/go-zkvm-verifier/leanvm"
)

// Inside your verification function:
// output is [32]byte: four little-endian u64 words committed by the guest.
digest, err := leanvm.Verify(elf, output, proof)
if err != nil {
    return err
}
if digest != trustedProgramDigest {
    return fmt.Errorf("unexpected program")
}
```

`leanvm.ProgramDigest(elf)` computes the program identity without checking a proof.
This digest is not a plain hash of the ELF file.

SP1 checks a compressed proof against the expected program key and public values:

```go
import "github.com/sm-stack/go-zkvm-verifier/sp1"

// Inside your verification function:
// key is [32]byte: eight canonical KoalaBear u32 words, each big-endian.
return sp1.Verify(key, publicValues, compressedProof)
```

Runnable fixture examples are in [leanvm/example_test.go](leanvm/example_test.go)
and [sp1/example_test.go](sp1/example_test.go). The SP1 fixture stores its key as
little-endian bincode words; the example converts them to the API representation.

## Use the CLI

Build and verify a shipped leanVM proof from the repository root:

```sh
CGO_ENABLED=0 GOMAXPROCS=2 go build -p 1 -o bin/stark-go-verify ./cmd/stark-go-verify
bin/stark-go-verify leanvm \
  -elf leanvm/testdata/fibonacci.elf \
  -output leanvm/testdata/fibonacci-1000.output \
  -proof leanvm/testdata/fibonacci-1000.proof
```

To run the SP1 fixture, unpack its proof and convert the key's word order:

```sh
python3 - <<'PY'
import gzip, pathlib, struct
p = pathlib.Path('sp1/testdata/fixture')
pathlib.Path('bin/sp1.proof').write_bytes(gzip.decompress((p/'proof.bin.gz').read_bytes()))
words = struct.unpack('<8I', (p/'vkey_hash.bin').read_bytes())
pathlib.Path('bin/sp1.key').write_bytes(struct.pack('>8I', *words))
PY
bin/stark-go-verify sp1 -vkey bin/sp1.key \
  -public-values sp1/testdata/fixture/public_values.bin -proof bin/sp1.proof
```

Files are raw binary inputs. Exit codes are **0** for acceptance, **1** for
rejection (including malformed proofs/ELFs), and **2** for usage or I/O errors.
`-h` exits 0. leanVM success also prints the program digest. Applications must
bind the program identity and claimed outputs/public values to trusted context.

The `leanvm` and `sp1` commands cap variable-size files at 64 MiB, except SP1
proofs at 16 MiB; fixed-size statements require exactly 32 bytes. Oversized
variable inputs exit 1, while incorrect fixed-size statements exit 2.

## Validation

Tests replay pinned Rust verdicts and program digests using fixtures shipped in
this repository. **Missing fixtures fail tests.** Ordinary Go tests require no
Rust installation or proof generation.

| Area | Coverage |
| --- | --- |
| leanVM | ELF/program digests, valid execution proofs, altered programs/outputs/proofs, malformed lengths, truncation and trailing bytes |
| SP1 | Primitive/constraint vectors, compressed-proof mutations, program-key/public-value binding, noncanonical encodings |
| Arithmetic | Bit-serial field reference, hardware/software agreement, scalar/generated Poseidon2, boundary values and fuzz comparisons |
| ELF and bytecode | Overlapping symbol tables, segment bounds/overlap, streaming slots/digests/evaluations against a materialized reference |
| Concurrency and CLI | Shared caches/verifiers, deterministic worker errors, exit codes, bounded reads, help and I/O failures |

The symbol reference parses records independently of the production interval
cache. Rust vectors separately check loader compatibility. SP1's full positive
fixture uses SHA-256 public-value commitments; BLAKE3 selection has unit coverage
but **no full positive proof fixture**.

Run checks from the repository root with Go 1.26+ and Python 3.9+:

```sh
CGO_ENABLED=0 GOMAXPROCS=2 go test -p 1 ./...
CGO_ENABLED=0 GOMAXPROCS=2 go test -tags purego -p 1 ./...
CGO_ENABLED=0 GOMAXPROCS=2 go build -p 1 ./...
CGO_ENABLED=0 GOMAXPROCS=2 go vet -p 1 ./...
CGO_ENABLED=1 GOMAXPROCS=2 go test -race -p 1 ./...
python3 tools/check_artifacts.py
python3 tools/gen_poseidon2.py --check
python3 tools/check_guards.py
```

Race instrumentation requires CGO; library and CLI builds do not. On arm64,
`GODEBUG=cpu.pmull=off go test ./leanvm` exercises the software fallback.
Artifact checks detect changed files; generator checks compare generated code;
guard mutations check that negative tests catch disabled rejection checks.

To regenerate Rust verdicts, digests and constraints with locked dependencies:

```sh
python3 tools/regenerate.py --check
```

This uses two build workers and verifies existing proofs. It does not generate
new execution proofs. Pins, fixture provenance, encoding policy and generator
instructions are in [UPSTREAM.md](UPSTREAM.md).

Run fuzz targets one at a time:

```sh
CGO_ENABLED=0 GOMAXPROCS=2 go test ./leanvm -run '^$' -fuzz '^FuzzVerify$' -fuzztime 30s -parallel 1
CGO_ENABLED=0 GOMAXPROCS=2 go test ./sp1 -run '^$' -fuzz '^FuzzVerify$' -fuzztime 30s -parallel 1
```

Additional targets cover decoders, fields and permutations. CI is configured to
run CGO-free tests on Linux/macOS, replay Rust vectors and run fuzz smoke tests.
The reference workflow regenerates Rust artifacts on pull requests or manual runs.

## Experimental extension: leanVM claim trees

`experimental/leanvmclaims` verifies sealed claim-tree roots for the sm-stack custom fork `op-stack/claim-set-leaves` at **`59c25cccfd5742f8216f259f9dd4d80d9a5f66e5`** (package version 0.1.0). A root authenticates program-labelled members from one or more leaf classes. Members are entries committed by a guest, not necessarily its execution output. The API is experimental.

Authenticate a class key once, then reuse the verifier concurrently:

```go
v, err := leanvmclaims.NewClassVerifier(classKeyBytes, trustedClassDigest)
if err != nil {
    return err
}
claims, err := leanvmclaims.ClaimsFromStatements(statements)
if err != nil {
    return err
}
return v.VerifySealed(claims, rootBytes, sealBytes)
```

`statements` is a canonical `[]leanvmclaims.Statement`, with `[32]byte` program and member digests. The caller pins the class-key digest independently, authorizes program identities, and supplies its intended members. Configuration comes from the authenticated key; `v.Config()` returns an independent snapshot for application policy checks. The package verifies root proofs and seals; proving, leaf-proof verification and same-program trees are outside its scope.

```sh
bin/stark-go-verify leanvm-claims -class-key class-key.bin -digest TRUSTED_64_HEX_DIGEST \
  -root root.bin -claims claims.bin -seal seal.bin
python3 tools/leanvm-mixed/regenerate.py --check
CGO_ENABLED=0 GOMAXPROCS=2 go test ./experimental/leanvmclaims -run '^$' -fuzz '^FuzzVerifySealed$' -fuzztime 30s -parallel 1
```

Tests replay one- and two-tier roots, rehashed descriptor mutations, and an Optimism operational-class aggregate against pinned Rust verdicts.

Class-key or digest errors exit **2**; rejected root/claims/seal inputs exit **1**. The command adds no byte-size cap. See [PORTING.md](experimental/leanvmclaims/PORTING.md) for the wire format, integration adapter, source mapping and fixture generation.

## Security assumptions and limits

- This port has **not received an independent cryptographic audit**. Soundness
  depends on the pinned protocol's arithmetic, transcript, hash and parameter
  assumptions, correct porting, and trusted program identity/public inputs.
- Differential tests cover a finite corpus. They do not prove equivalence for
  every input, absence of panics, or protocol soundness.
- SP1 retains its source adapter's 16 MiB proof cap, 32 distinct opened-chip cap,
  64-byte chip-name cap and complete-consumption check. The unrestricted upstream
  raw API differs. [UPSTREAM.md](UPSTREAM.md#compatibility-boundary-and-input-limits)
  defines this compatibility boundary.
- leanVM follows upstream ELF memory-map bounds and adds no library proof-size
  cap. Streaming bytecode evaluation reduces memory use, but work still scales
  with the logical encoding. Resource limits imposed by a service or CLI can
  reject upstream-valid inputs. Budget CPU and memory for untrusted requests.
- Verification inputs are public; no constant-time guarantee is made. Error
  strings are not a stable API.

Proof encodings need not be unique. Bind replay protection to the verified
program and application statement, including a nonce or sequence number, rather
than a hash of raw proof bytes.

## Performance and license

Both leanVM verifiers share optional arm64 PMULL assembly with runtime CPU detection; other
architectures use portable Go. `-tags purego` selects the portable backend.
SP1 uses generated Go Poseidon2 code and may use one extra worker for large
Merkle batches when `GOMAXPROCS > 1`. See [PERFORMANCE.md](PERFORMANCE.md) for
measurements and benchmark commands.

MIT; upstream attribution and license texts are preserved in [NOTICE](NOTICE)
and [LICENSES](LICENSES).
