# stark-go-verify

Go verification of leanVM execution proofs and SP1 compressed proofs. No Rust
runtime, CGO, prover, network access, or chain client is needed by the library or CLI.
Module: `github.com/sm-stack/go-zkvm-verifier` (from this repository's Git remote).
Requires Go 1.26 or later. leanVM uses optional arm64 PMULL Go assembly with
runtime CPU detection; `-tags purego` forces its portable Go implementation.
Other architectures currently use the portable leanVM field implementation.
Hash dependencies may use assembly; no CGO or Rust runtime is required. SP1 verifier logic uses Go
source only and may use one additional worker for large Merkle batches when
`GOMAXPROCS > 1`. See [PERFORMANCE.md](PERFORMANCE.md) for benchmark results.

| Package | Supported upstream | Statement |
| --- | --- | --- |
| `leanvm` | sm-stack/leanVM fork 0.1.0, commit `c3fc7b2a9195ed995f7f7e9f8245ad6e8a4dfb14` | RV64 guest ELF + 32 output bytes; LVMP version 1 |
| `sp1` | SP1 6.8.1, commit `c84ada1ed5911f28c4d3c9d0ed2f9e6cd7edb824` | program verifying-key digest + public values; bincode `SP1Proof::Compressed` |

The `leanvm` package also targets a specific sm-stack fork revision, not
upstream leanVM main. Neither leanVM package promises compatibility with other
commits. The custom claim-tree protocol is documented separately under
[experimental extensions](#experimental-extension-leanvm-claim-trees).

SP1 uses KoalaBear, the pinned recursion-key tree, and the layout **without
`mprotect`**. Core, Plonk, Groth16, other SP1 releases, and proof generation are
outside this library's scope. The packages deliberately have separate APIs.
There is no Optimism aggregate payload, RPC, registry, or derivation integration.
Formal verification (including Lean) is outside this project.

```go
import (
    "github.com/sm-stack/go-zkvm-verifier/leanvm"
    "github.com/sm-stack/go-zkvm-verifier/sp1"
)

// output is [32]byte: four little-endian u64 words, exactly as committed by the guest.
digest, err := leanvm.Verify(elf, output, proof)
// A nil error means this execution statement was accepted.
// Compare digest with the program digest your application trusts.

// key is [32]byte: eight canonical KoalaBear u32 words, each BIG-endian.
err = sp1.Verify(key, publicValues, compressedProof)
```

`leanvm.ProgramDigest(elf)` computes a program digest without verifying a proof.
An ELF is not identified by a plain file hash. Successful verification returns
its program digest; error return values must be checked before using that digest.
Runnable examples with the shipped fixtures are in each package's
`example_test.go`. SP1 fixture keys use **little-endian bincode words**; the
example shows their conversion to the API's big-endian representation.

Build and use the CLI from the repository root:

```sh
CGO_ENABLED=0 GOMAXPROCS=2 go build -p 1 -o bin/stark-go-verify ./cmd/stark-go-verify
bin/stark-go-verify leanvm \
  -elf leanvm/testdata/fibonacci.elf \
  -output leanvm/testdata/fibonacci-1000.output \
  -proof leanvm/testdata/fibonacci-1000.proof

# Unpack the transport compression, and convert the fixture's key word order.
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

The CLI reads raw binary files. Exit codes: **0** accepted, **1** rejected
(including malformed proof or ELF), **2** invalid usage or file I/O failure.
leanVM success prints `accepted` and the program digest. Applications must bind
the claimed output/public values and program identity to their own trusted context.

Validation commands (low parallelism):

```sh
python3 tools/check_artifacts.py
CGO_ENABLED=0 GOMAXPROCS=2 go test -p 1 ./...
CGO_ENABLED=0 GOMAXPROCS=2 go test -tags purego -p 1 ./...
python3 tools/gen_poseidon2.py --check
CGO_ENABLED=0 GOMAXPROCS=2 go vet -p 1 ./...
CGO_ENABLED=0 GOMAXPROCS=2 go test -p 1 ./leanvm ./sp1 -run '^$' -bench . -benchmem
CGO_ENABLED=0 GOMAXPROCS=2 go test ./leanvm -run '^$' -fuzz '^FuzzVerify$' -fuzztime 30s -parallel 1
CGO_ENABLED=0 GOMAXPROCS=2 go test ./sp1 -run '^$' -fuzz '^FuzzVerify$' -fuzztime 30s -parallel 1
```

Both packages also expose decoder fuzz targets. CI builds and tests with
`CGO_ENABLED=0` on Linux and macOS, replays checked-in Rust verdicts, checks artifact
hashes, and runs bounded fuzz smoke tests. Missing fixtures fail tests. A separate
reference workflow regenerates Rust artifacts and compares them on PRs or manual runs.
See [UPSTREAM.md](UPSTREAM.md) for source pins, licenses, fixture provenance,
regeneration instructions, and encoding policy, and [VALIDATION.md](VALIDATION.md)
for test coverage and reproduction commands.

## Security assumptions and limits

- This is a port of the pinned verification algorithms, not an independently
  audited cryptographic implementation. Soundness depends on upstream protocol,
  arithmetic, Fiat–Shamir transcript, hash, and parameter assumptions, as well as
  correct porting and trustworthy program identity/public inputs.
- Differential tests establish agreement on a finite corpus. They do not prove
  equivalence for every byte string, absence of panics, or protocol soundness.
- SP1 rejects encoded proofs larger than 16 MiB, more than 32 distinct opened
  chips, and opened chip names longer than 64 bytes. These follow the source Rust
  adapter's policy; upstream's raw API allows trailing bytes and has no 16 MiB
  limit. See the explicit compatibility boundary in UPSTREAM.md.
- leanVM uses upstream ELF memory-map bounds, including checks that prevent a
  small ELF from expanding into a sparse, huge initialized image. It adds no
  separate proof byte limit. ELF symbol lookup reuses previously scanned ranges without an additional
  work-budget rejection; see UPSTREAM.md. Bytecode digesting streams the original slot-major encoding, and bytecode
  evaluation uses bounded scratch instead of materializing the expanded table.
  This adds no input rejection rule, but hashing time still scales with the
  expanded encoding. Neither package promises a fixed time/memory budget.
  Callers handling untrusted inputs should impose their own transport limits and
  process-level resource budgets; tighter limits may reject upstream-valid proofs.
- No constant-time guarantee is made; verification inputs are public. An API error
  means rejection, with no stable error-string compatibility guarantee.

License: MIT for this extraction; upstream notices and additional license texts
are preserved in [NOTICE](NOTICE) and [LICENSES](LICENSES).

Proof encodings are not unique: upstream-compatible noncanonical field words
and reordered/duplicate map keys can encode the same SP1 proof. Bind replay
protection to the verified program and application statement (including a nonce
or sequence number), not a hash of raw proof bytes.

The `leanvm` and `sp1` CLI subcommands cap variable-sized inputs at 64 MiB (SP1 proofs: 16 MiB) and reads
fixed-size statements with a 32-byte limit. `-h` exits 0; output write failures
exit 2. See UPSTREAM.md for differences from upstream's raw API and ELF
symbol-search compatibility.


## Experimental extension: leanVM claim trees

`experimental/leanvmclaims` verifies sealed claim-tree roots that aggregate
execution claims from multiple programs. It targets the **sm-stack custom fork**
`op-stack/mixed-program-tree` at commit
`da5c964831c993b011464e4fd4a573b7172d5295` (package version 0.1.0).
It is not a verifier for upstream leanVM main and is separate from the
standalone execution-proof API. Its API and supported protocol may change.

Load the authenticated class once, then reuse the verifier concurrently:

```go
import "github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims"

v, err := leanvmclaims.NewClassVerifier(classKeyBytes, trustedClassDigest, expectedClass)
if err != nil { return err }
return v.VerifySealed(rootBytes, claimSetBytes, sealBytes)
```

`expectedClass` is a `leanvmclaims.ClassConfig` containing program dimensions, leaf
heights, rates, arities and claim capacities. Both it and `trustedClassDigest`
must be trusted independently of submitted bytes. The root verifier checks
first-level and one-/two-tier mixed trees; leaf proving/verification and
same-program trees are outside this API.

```sh
stark-go-verify leanvm-claims -class-key class-key.bin -digest TRUSTED_64_HEX_DIGEST \
  -class expected-class.json -root root.bin -claims claims.bin -seal seal.bin
```

The JSON uses `ClassConfig` field names (`LogBytecode`, `LogRAM`, `LogAdvice`,
`ImageWords`, `LeafHeights`, `LeafRate`, `Arity0`, `Arity`, `TreeRate`, `Claims`,
`Groups`, optional `Small` with `Arity`/`Claims`/`Groups`). Files are raw upstream
encodings. Exit codes remain 0 accepted, 1 rejected, 2 usage/I/O error; help is 0.
The `leanvm-claims` subcommand adds no byte-size cap; services must budget resources for
their trusted class. [Full protocol, fixtures and reproduction](experimental/leanvmclaims/PORTING.md).
