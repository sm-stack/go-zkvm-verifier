# Upstream pins and provenance

## Source extraction

The original Optimism source was inspected read-only at clean HEAD
`28c4c5b77f7b713ac081e40963eead49c26e2c18`, origin
<https://github.com/sm-stack/optimism>. No runtime, test, or regeneration
command in this repository depends on the original workspace. The Go module follows this
repository's origin `https://github.com/sm-stack/go-zkvm-verifier.git`;
**stark-go-verify** is the project and binary name.

The Optimism commits below identify the local extraction history; they are not
fetchable build dependencies or a guarantee that those commits are published.
All required extracted sources and fixtures are included here; Rust regeneration
uses the separate pinned upstream dependencies below.

Copied sources:

| Source at the extraction commit | Destination / treatment |
| --- | --- |
| `op-core/leanvm/*.go` | `leanvm/`; public `common.Hash` replaced by `[32]byte`, test hex helpers made local, fixture paths relocated |
| `rust/op-leanvm-proofs/testdata/*` | `leanvm/testdata/`; bytes unchanged |
| `op-core/leanvm/testdata/vectors.json` | `leanvm/testdata/vectors.json`; reproduced from pinned Rust |
| `op-core/sp1verifier/` | `sp1/`; package renamed, generator path updated, fixture bytes unchanged |
| `rust/op-leanvm-proofs/examples/go_vectors.rs` | `tools/leanvm/examples/go_vectors.rs`; output/fixture paths and adapter name changed |
| `rust/op-sp1-proofs/examples/go_verifier_tables.rs` | `tools/sp1/examples/go_verifier_tables.rs`; package/path names changed, statement verdict generation added |
| Rust verifier adapters | minimal `tools/*/src/lib.rs`; chain types, aggregate traits and registry integration removed |

`op-node/rollup/derive/dependency_scanner.go` and `dependency_leanvm_test.go`
were inspected for integration context, not copied. They test aggregate and
chain policy outside standalone proof verification. leanVM and SP1 arithmetic
remain separate because their binary-field and KoalaBear machinery have different
semantics. The two leanVM verifiers share `internal/gf2`. Existing source comments were retained except stale integration,
package and generation instructions; original files had no individual license
headers to remove. New CLI, examples, robustness tests, provenance checks and CI
are local additions. No protocol-level fix was needed by the observed corpus.

## leanVM

- Repository: <https://github.com/sm-stack/leanVM>
- Version: workspace crates **0.1.0**; version alone does not identify this fork.
- Commit: **`c3fc7b2a9195ed995f7f7e9f8245ad6e8a4dfb14`**.
- Rust reference: `leanvm::Program::from_elf`, `Proof::from_bytes`,
  `leanvm::verify`, and `Program::digest`.
- Proof format: `LVMP`, little-endian u16 version **1**, fixed-width
  little-endian bincode body, no trailing bytes.
- Port: field arithmetic, instruction tables/circuits, ELF loading, program digest,
  transcript, bus balance, sumchecks, flock/ring switching and WHIR/Merkle checks.
  The verification flow follows the fork's `python-verifier/verifier.py`, with
  Rust as the digest/decoding/acceptance reference.
- Licenses: upstream root `LICENSE-MIT` (leanEthereum, 2026) and
  `LICENSE-APACHE`; copies under `LICENSES/`. The Go extraction comes from the
  Optimism MIT tree; see NOTICE.

Fixtures are upstream Fibonacci and preimage guests, copied from the source
Rust package. `fibonacci-1000` proves advice n=1000 at inverse rate 2;
`preimage-40000` proves the preimage guest with a 40000-byte message at inverse
rate 16. ELF/proof/output bytes are checked in, not downloaded. The source
example's original proving instructions and message word pattern are retained
in `tools/leanvm/examples/go_vectors.rs`; this project's normal regeneration
only **verifies** existing proofs. Guest source/linker scripts are available
under `programs/` at the exact upstream commit. Rebuilding ELF files requires
its RISC-V toolchain and is separate from replaying the shipped proofs.

The Rust-generated corpus contains **1061 ELF/digest cases** and **646 proof
cases** (10 accept), including header/symbol/text changes, wrong outputs/programs,
truncations, extensions, malformed lengths and noncanonical transcript roots.
Both `ProgramDigest` and successful `Verify` digests are compared. Invalid ELF
cases expect loader rejection. All program/digest and proof fixtures are required.

## SP1 compressed

- Repository: <https://github.com/succinctlabs/sp1>
- Crates: **6.8.1**, exact requirements in `tools/sp1/Cargo.toml` and full
  transitive versions/checksums in its `Cargo.lock`.
- Commit: **`c84ada1ed5911f28c4d3c9d0ed2f9e6cd7edb824`**, recorded in
  the published crates' `.cargo_vcs_info.json` (checked locally for verifier,
  primitives, hypercube and slop-algebra).
- `sp1-verifier` crate checksum:
  `aca7223cc7a77e42536c7229c8016672737aab07f6149097d9c7a26324b29814`.
- Rust reference: `SP1CompressedVerifier::verify_compressed_with_public_values`.
- Features: `sp1-verifier/full`, other SP1/slop dependencies without default
  features; **mprotect disabled**, asserted by the generator and adapter.
- Wire: bincode legacy fixed-width little-endian `SP1Proof::Compressed`, enum
  variant index 1. This is not an SDK envelope or the other SP1 proof variants.
- Port: KoalaBear/quartic extension, Poseidon2, challenger, LogUp-GKR,
  zerocheck, jagged PCS, stacked Basefold and recursion verifying-key membership.
- Generated `sp1/compress_machine_gen.go`: 8 compress AIR chips, constraint DAGs,
  interactions, Poseidon2/FRI parameters, public-value offsets and recursion-key
  tree constants. Generator records constraints with its own builder to keep
  preprocessed columns distinct, and checks machine-shape assumptions.
- License: SP1 crates declare **MIT OR Apache-2.0**. Both upstream license texts
  were retrieved from the pinned commit and are preserved under `LICENSES/`.
  [MIT source](https://github.com/succinctlabs/sp1/blob/c84ada1ed5911f28c4d3c9d0ed2f9e6cd7edb824/LICENSE-MIT),
  [Apache source](https://github.com/succinctlabs/sp1/blob/c84ada1ed5911f28c4d3c9d0ed2f9e6cd7edb824/LICENSE-APACHE).

The fixture first appeared in Optimism source commit
`03c41c671bf9c5cfe49bf881ebcf287d0f04728b`. It is a compressed proof of a
Fibonacci guest (n=1000000; public values are two little-endian u64s). Its
uncompressed bytes match the original workspace's PoC fixture. The recovered
small guest source is preserved at `tools/fixture-sources/sp1-fibonacci.rs`;
SP1 SDK 6.8.1 generated the source workspace fixture. This extraction does not
claim bit-for-bit reproducibility of the original guest build or randomized
proof generation. It preserves the already generated proof, its Rust verifier,
and every input needed to regenerate verdicts. No original `.context` is needed.
The fixture is distributed as part of the source MIT tree, with the SP1 notices
retained. No secret advice or proving key is required for replay.

The proof is **1,272,546 bytes**, stored as an **805,375-byte gzip**. Its
uncompressed SHA-256 is
`ef711a5f80641b6382f5de136ba11f4e73420ada6264cbae576bfbeff486d3fd`.
All fixture and generated-file sizes/hashes are in `artifacts.json`.
The corpus has **583 Rust proof mutations** (281 accept), primitive/chip vectors,
and **6 statement verdicts**. It checks truncation, trailing data, lengths, enum
and option tags, UTF-8, tensor dimensions, key ordering/duplication, noncanonical
field representatives, proof corruption, wrong public values and wrong keys.
Noncanonical proof field words are reduced as upstream serde does; rejecting
all such encodings would introduce a compatibility bug. Statement keys must
be canonical, in eight big-endian words; the fixture's key is little-endian.

## Compatibility boundary and input limits

Rust verdicts use the upstream algorithms behind a minimal standalone adapter
retaining the original source byte-decoding policy, not Optimism aggregation.
SP1 6.8.1's upstream raw API (`compressed/mod.rs`, `verify_with_public_values`) uses bincode
1.3.3 `deserialize`: it accepts trailing bytes, has no 16 MiB transport cap,
and accepts the program key in little-endian word order. This Go API instead
matches the standalone adapter below and takes big-endian key words.
The adapter uses bincode **2.0.1 serde legacy**, checks complete consumption,
and sets its decode limit to **16 MiB**, with at most **32 distinct opened chips**
and **64 bytes per opened chip name**. Go retains those checks. Bincode's serde
sequence/map path counts decoded scalar bytes; it does not cap total allocator
RSS. The Go decoder also checks every declared length against remaining bytes
before allocating. Neither decoder's byte limit is a total memory limit.

Compared with the unrestricted upstream typed verifier (or another caller using
an unlimited bincode decoder), Go can reject large byte encodings that represent
the same valid proof. Repeated map keys are an example of redundant encodings:
the last value wins. This is an intentional transport-policy restriction, not
claimed universal accept/reject equivalence with every possible SP1 caller.
Within the checked-in and freshly regenerated corpus there are **no observed
Go/Rust verdict or digest differences**. Acceptance at every size-boundary or
for every possible redundant encoding is not exhaustively established.
leanVM's memory-map/file-size bounds follow the pinned Rust loader. Symbol lookup
caches fully scanned unmatched record ranges, separated by string-table offset,
string-table length and record alignment. It validates every table header before
using the cache, preserving first-match and malformed-table ordering. Empty tables
are validated but not cached. The Rust corpus includes overlapping symbol-table
views that preserve the program digest and accept its original proof. Distinct
string tables can still require repeated scans. No separate Go library
proof-size limit is imposed for leanVM.

The CLI caps each ELF, leanVM proof and public-values file at **64 MiB**;
SP1 proofs use the library's **16 MiB** cap and fixed statements require exactly
32 bytes. Regular files are checked before allocation; other files are read
through a limit. Exceeding a variable-size cap returns rejection (1), while
incorrect fixed-size statements return usage error (2). CLI caps can reject
inputs accepted by the libraries or upstream. These are transport/work policies,
not claims about the cryptographic validity of an oversized input.

## Reproduction

From this repository root, with Go 1.26+, Python 3.9+ and Rust/Cargo available
(tested Rust 1.99.1):

```sh
# Verify inventory, hashes and byte sizes without Rust.
python3 tools/check_artifacts.py
# Build only the pinned reference tools and compare regenerated artifacts.
python3 tools/regenerate.py --check
# Intentionally replace artifacts after reviewing a pin/generator change.
python3 tools/regenerate.py
python3 tools/check_artifacts.py --update
```

The script uses `cargo run --locked --release -j 2`, `RAYON_NUM_THREADS=2`,
existing fixtures, temporary output directories and `gofmt`. It performs no
proof generation. It compares leanVM verdict/digest JSON, SP1 generated Go,
primitive/chip JSON, mutation verdicts, and statement verdicts byte-for-byte.
Its two small Cargo workspaces have independent locks seeded from the original
Rust workspace lock, pruned by Cargo; no OP Stack crates are dependencies.
Initial network access may be needed to fetch pinned sources. A fresh SP1
reference build can use several hundred MB or more and take minutes; ordinary
Go CI requires no Rust. The reference CI runs the same comparison.

## Local performance implementations

`internal/gf2/clmul_arm64.s` implements the pinned GF(2^64) reduction polynomial and
six-product GF(2^192) multiplication using Go PMULL assembly. Both leanVM
verifiers use this shared backend: their base-field polynomial, extension
polynomial and three-limb coefficient order are identical. CPU dispatch, portable fallback and
`purego` builds preserve the same field operations and program digests. No
assembly is called without PMULL detection. amd64 currently uses Go fallback.

`sp1/poseidon2_fast_gen.go` is generated by `tools/gen_poseidon2.py`. It uses the upstream constants already
reproduced by the Rust generator; no new constants or protocol parameters are
introduced. Regenerate with `go generate ./sp1`, then update artifact hashes with
`python3 tools/check_artifacts.py --update`. Check without modifying files with
`python3 tools/gen_poseidon2.py --check`. The file is included in artifacts.json.
Scalar reference permutation and bit-serial field arithmetic are tested separately.

## Experimental leanVM claim trees (custom fork protocol)

`experimental/leanvmclaims` supports sm-stack/leanVM package 0.1.0 at
`da5c964831c993b011464e4fd4a573b7172d5295`, branch
`op-stack/mixed-program-tree`. It authenticates LVMXCK01 class keys, LVMT v20
roots and framed mixed-tree-seal/v2 seals. The standalone leanVM and SP1 pins above are unchanged. See
[the experimental claim-tree verifier documentation](experimental/leanvmclaims/PORTING.md) for the complete
Go/Rust source mapping, fixture licensing, regeneration commands, scope and
resource policy. Full verification includes recursion, carried matrix claims
and fixed-polynomial openings; loader/component checks alone do not accept roots.
