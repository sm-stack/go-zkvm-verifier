# Experimental leanVM claim-tree verifier

This package verifies sealed roots of program-labelled member sets. It implements the custom `op-stack/claim-set-leaves` protocol in [sm-stack/leanVM](https://github.com/sm-stack/leanVM/tree/59c25cccfd5742f8216f259f9dd4d80d9a5f66e5), package 0.1.0, commit **`59c25cccfd5742f8216f259f9dd4d80d9a5f66e5`**. It is independent of the standalone ELF/proof verifier in `leanvm/` and is not upstream leanVM main's protocol.

## API and trust

```go
v, err := leanvmclaims.NewClassVerifier(classKey, trustedDigest)
if err != nil {
    return err
}
claims, err := leanvmclaims.ClaimsFromStatements(statements)
if err != nil {
    return err
}
return v.VerifySealed(claims, root, seal)
```

The constructor authenticates the complete key using `BLAKE2s-256("leanvm/mixed-class-key/v2" || encoding)`, reads its ordered leaf classes and tree configuration, validates the layout, and owns a copy of the bytes. The digest must come from trusted application configuration. Hashing an attacker's self-selected key does not authorize its circuits. Load once and reuse concurrently; proof and claim slices must remain unchanged during verification. Constructor errors wrap `ErrClass`; verification errors wrap `ErrProof`.

The application separately authorizes normalized program VK digests and supplies the intended members. A member is an entry of the list committed by a guest, not necessarily the execution output. For a signature guest, the application must recompute the intended key/message member and enforce any freshness or replay policy.

`ClaimsFromStatements` maps `VkeyHash` into four little-endian uint64 label words followed by two zero words, and `PublicValuesDigest` into four little-endian member words. It requires canonical order and rejects duplicates without sorting. Order is lexicographic over unsigned words: bytewise ordering of the 32-byte digest is not equivalent. `DecodeClaims` on the loaded verifier accepts raw upstream claim-set bytes under the authenticated capacities. `EncodeClaims` serializes canonical sets.

A thin op-node adapter can be implemented in the application's module, without adding chain types to this library:

```go
func aggregateVerifier(v *leanvmclaims.ClassVerifier) ProofAggregateVerifier {
    return func(statements []optypes.ProofStatement, root, seal []byte) error {
        input := make([]leanvmclaims.Statement, len(statements))
        for i, s := range statements {
            input[i] = leanvmclaims.Statement{
                VkeyHash: [32]byte(s.VkeyHash),
                PublicValuesDigest: [32]byte(s.PublicValuesDigest),
            }
        }
        claims, err := leanvmclaims.ClaimsFromStatements(input)
        if err != nil {
            return err
        }
        return v.VerifySealed(claims, root, seal)
    }
}
```

`statements.json` tests this conversion against Rust `ClaimSet::from_claims` followed by an input-equality check. The Optimism adapter uses the same mapping; it is integration code in a separate repository, not part of the leanVM pin. It includes cases whose byte and numeric word ordering differ.

## Protocol and resource policy

The supported encodings are `LVMXCK02` class keys, `LVMT` envelope version 21, and framed seal session `SessionId::tagged("leanvm/mixed-tree-seal/v2", class_key_digest)`. Root sessions use `leanvm-tree-18` and `/mixed-members/2`, including every leaf descriptor and member capacity. Other versions, malformed encodings and trailing data are refused.

Each leaf class has its own first-level circuit. A **first-level root** aggregates leaf executions; a **small node** combines child roots within the small tier. **Wide** is the large-capacity tier. A **wrap** represents a large-tier child in the small tier for further aggregation. All first-level classes share small-tier padded heights. Kind codes bind the tier, local circuit index and first/node marker; the selected key supplies the fixed columns.

Verification checks the recursion transcript, flock, GKR bus, constraints, witness openings and EOF, then settles matrix and fixed-polynomial claims. Every first-level root has an empty seal, including nonzero class indices. Changing only the seal session therefore does not invalidate that empty seal; node and wrap seals bind it. The checked constructor independently rejects all key/digest mismatches before any proof is accepted.

The package supports plain mixed trees with one or two tiers. Proving, circuit building, leaf-proof verification, same-program trees, zero-knowledge leaves and formal verification are outside its scope. Runtime code requires neither Rust nor CGO. Shared `internal/gf2` uses arm64 PMULL with runtime feature detection, or a portable fallback selected by `purego` and on other architectures.

There is no additional library byte budget. The key is copied once; fixed columns are read in place, and placeholder zero images are hashed without materializing program tables. Root statement and decoded claim allocations are checked against the authenticated class. Other transcript data is read from supplied slices. CPU and memory still depend on the class and input sizes; service limits are application policy and may reject upstream-valid inputs. See the repository [security assumptions](../../README.md#security-assumptions-and-limits).

The CLI reads raw binary regular files. It authenticates the key before reading root/claims/seal. Success exits 0, proof/claim/seal rejection 1, invalid class key/digest, usage or I/O errors 2. There is no default file-size cap.

## Fixtures and reproduction

All required tests use committed fixtures and fail if any are missing or have the wrong pin/hash. Genuine proof directories carry uncompressed SHA-256 hashes and sizes in `provenance.json`; `artifacts.json` also covers stored files and generated constants. Fixture generation uses Rust at the pinned commit. Upstream licensing and attribution are retained in `NOTICE` and `LICENSES/`.

| Artifact | Coverage |
| --- | --- |
| `one-tier.key.gz`, `two-tier.key.gz`, `classes.json` | Explicitly labelled loader-only zero-column derivatives of Rust setup keys; semantic mutations and placeholder digests, not positive proof fixtures |
| `roots/` | Two-class constant-member guests: `first` (K=4 including a duplicate), `first-class1` (K=1), `one-member`, `small-node`, `wide`, `fold-dedup` |
| `root-components.json` | Full Rust verdicts for the six roots, region byte flips, cuts, wrong claims/matrices and malformed/swapped seals |
| `forgery/` | `assert_fake_large_wrap_refused`: forged child fails recursion; wrap recursion passes but authenticated settlement fails |
| `member-attacks/` | Upstream member-list forgeries, foreign-kind/fixed-polynomial attack, and valid roots of both classes including actual leanSPHINCS signatures |
| `statements.json` | Statement conversion, canonical order and duplicate rejection |
| Component JSONs | Rust fields, transcripts, wire formats, Merkle, WHIR, stack, flock, layouts and matrix evaluation |

The member attack exporter retains the upstream assertions, including row-level list/shape tests, folds, capacity rollback, and the first-level empty-seal exception. The Go tests replay exported root outcomes; leaf row tests themselves run only in Rust.

```sh
CGO_ENABLED=0 GOMAXPROCS=2 go test -p 1 ./...
CGO_ENABLED=0 GOMAXPROCS=2 go test -p 1 -tags purego ./...
CGO_ENABLED=1 GOMAXPROCS=2 go test -race -p 1 ./...
python3 tools/check_artifacts.py
python3 tools/leanvm-mixed/regenerate.py --check
```

Explicit proof generation uses two workers. All source modifications happen in disposable exact-pin checkouts and add inspection/export adapters; no original workspace or Cargo checkout is edited.

```sh
python3 tools/leanvm-mixed/regenerate.py --export-proofs /tmp/claim-proofs
python3 tools/leanvm-mixed/pack_proofs.py /tmp/claim-proofs --check
python3 tools/leanvm-mixed/generate_forgery.py --check
python3 tools/leanvm-mixed/generate_attacks.py --check
# After intentional updates:
python3 tools/leanvm-mixed/regenerate.py
python3 tools/check_artifacts.py --update
```

The production benchmark is generated on demand and is not committed:

```sh
python3 tools/leanvm-mixed/generate_production.py /tmp/claim-production
```

This invokes upstream `examples/claim_set_leaves.rs` with 100 signatures and claim bound 4097, two workers, and only its two-class case. Its 357-claim root crosses the small-tier capacity. See [PERFORMANCE.md](../../PERFORMANCE.md) for measurements and commands.

## Source mapping

Rust paths below are relative to `crates/leanvm_core/src/` unless a crate is named.

| Go | Pinned Rust |
| --- | --- |
| `classkey/key.go` | `rec/tree/embed.rs::mixed_classes_from_bytes`, `descriptor`, `Words` |
| `classkey/semantic.go` | `rec/tree/design.rs::new`, `session_tag`, `code`; `cpu/key.rs` digest |
| `claims.go`, `wire/proof.go` | `rec/tree/multiset.rs::ClaimSet`; `rec/tree/proof.rs::from_bytes` |
| `machine/` | `rec/layout.rs`, `rec/fixed.rs`, `cpu/layout.rs`, flock circuits and rec constraints |
| `transcript/`, `blake/` | `fiat_shamir` session, duplex, proof, POW; `primitives/hash` |
| root `internal/gf2`, package `field/` | `primitives/field/gf2_64.rs`, `gf2_64x3` |
| `pcs/` | `pcs` Merkle, WHIR and stacked openings |
| `flock/` | `flock` zerocheck, skip domain, lincheck and matrix settlement |
| `recursion/` | `rec/proof.rs`, GKR bus specialization and constraints |
| `settlement/` | `rec/tree/design.rs::position`, `mod.rs::verify_claims`, `seal.rs::fixed_polys` and seal verification |
| `verifier.go` | checked class load and `rec/tree/seal.rs::verify_claims_sealed` |

The package paths in the table are under `internal/` except `claims.go` and `verifier.go`. Generated `metadata-review.json` summarizes dimensions and gate hashes for source review; it does not replace the full constraint data. Check it offline with `python3 tools/leanvm-mixed/export_metadata.py --summary-only --check`.

### Operational class fixture

`testdata/production` replays Optimism's six-statement aggregate (program executions
and signatures) with the `b20ff9b907b2320fb8139f2753172235ae2e0a66fbad11c4a55500dfb4d33b50`
class key. The raw key is 60,027,800 bytes; the compressed corpus is about 12 MiB.
The class and source payload snapshot are under `tools/leanvm-mixed/production`;
its provenance records the Optimism base commit and SHA-256 of the uncommitted
inputs. The base commit alone does not reproduce that working tree. These files
use Optimism's MIT license, preserved in LICENSE and NOTICE.

`Config()` returns a deep copy of the authenticated descriptor for applications
that additionally enforce capacity or leaf-class policy. Authentication still
requires an independently trusted digest. The constructor keeps its defensive
copy so caller aliases cannot alter an active verifier.

Rebuild the operational key and extract its proof without generating new proofs:

```sh
cargo run --locked --release -j 2 --manifest-path tools/leanvm-mixed/Cargo.toml --bin production_key -- /tmp/claims-production
python3 tools/leanvm-mixed/production_fixture.py /tmp/claims-production --check
```

`regenerate.py --check` checks this key, extracted inputs, and the full Rust verdict
vectors. `production/fixtures.rs` records the source proof-generation example;
re-running the entire Optimism prover additionally requires its snapshotted
integration implementation, which is not vendored here. Existing proof bytes
are self-contained and verified by the pinned Rust verifier.

The one-tier positive corpus is regenerated with `tier_proofs -- OUT --one-tier`
and packaged with `pack_proofs.py OUT --one-tier`. Authenticated descriptor
mutations recompute the digest and compare the checked Rust loader, including a
valid changed member capacity that Rust accepts. Authentication-failure tests
remain separate. Root-rate, nonempty seals, and one-tier node layout selection
have explicit regressions.

The one-tier corpus uses leaf rates 1 and 2, exercising the additional leaf-rate
binding in the root session. Malformed class vectors also include zero leaf
count and an unsupported small-tier flag. Duplicate defensive checks remain in
place; a surviving removal mutant is not necessarily a reachable acceptance bug.

### Scratch cache policy

`SetScratchCacheLimit(bytes)` sets a process-wide retained scratch budget,
defaulting to 24 MiB. `SetScratchCacheLimit(0)` immediately drops the cached
buffer and disables subsequent retention, including returns from in-flight
verifications. The setting is safe to change concurrently and does not alter
proof acceptance. It does not limit live verification memory or loaded class
keys. Concurrent verifications own separate buffers, with at most one retained
when they finish. Negative budgets return an error without changing policy.
