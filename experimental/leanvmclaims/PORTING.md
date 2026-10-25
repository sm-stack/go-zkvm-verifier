# Experimental leanVM claim-tree verifier

This package verifies sealed roots that aggregate execution claims from multiple
programs. It targets the custom mixed-program tree protocol at
[`sm-stack/leanVM`](https://github.com/sm-stack/leanVM/tree/da5c964831c993b011464e4fd4a573b7172d5295)
commit **`da5c964831c993b011464e4fd4a573b7172d5295`** (`op-stack/mixed-program-tree`,
upstream package version 0.1.0). The separate
`leanvm` package retains its separate older protocol and pin.

This extension is experimental and is not compatible with upstream leanVM main.
Its Go package is `experimental/leanvmclaims`; the CLI command is `leanvm-claims`.
Upstream source names, wire identifiers and cryptographic domain tags retain
“mixed” because they define the pinned protocol.

## API and scope

```go
v, err := leanvmclaims.NewClassVerifier(classKey, trustedDigest, expectedClass)
if err != nil {
    return err
}
return v.VerifySealed(root, claims, seal)
```

`ClassConfig` includes program dimensions, all eleven leaf heights, both rates,
arities, claim/group capacities, and an optional `SmallTier`. Load the key once
and reuse the immutable verifier concurrently. Constructor input bytes and the
small-tier configuration are copied. Proof inputs must remain unchanged while
`VerifySealed` reads them. Errors wrap `leanvmclaims.ErrClass` or `leanvmclaims.ErrProof`.

Supported: plain mixed-tree first-level roots, small nodes, large/Wide nodes and
wraps; one- and two-tier classes; root claims and fixed-polynomial seals.
Runtime code is Go, without Rust or CGO. Leaf proof verification, proving,
circuit building, zero-knowledge leaves, same-program trees and formal
verification are outside this package's scope. It is not interchangeable with
the `leanvm` package's ELF/LVMP verifier.

The checked constructor authenticates the complete `LVMXCK01` key using
`BLAKE2s-256("leanvm/mixed-class-key/v1" || encoding)` and compares the expected
class descriptor. `trustedDigest` and `expectedClass` must come from a trusted
source, independent of the submitted key/proof. A valid hash of an attacker’s
own key is not a trusted class. Circuit data is a security-critical input:
this verifier does not rebuild the circuits to authenticate a self-selected key.

Roots use `LVMT` version 20. Seals use the exact framed
`SessionId::tagged("leanvm/mixed-tree-seal/v2", class_key_digest)` derivation.
The full path verifies the root's transcript, flock reduction, GKR bus balance,
table constraints, witness openings and EOF; it then settles the carried matrix
claims and fixed-polynomial openings. Claim-set ordering/capacities and digest
binding are required. No component success alone accepts a root.

## Limits and security assumptions

The library uses the pinned upstream size/profile checks. It introduces no
additional class-key/proof byte budget. Dummy program/witness tables are not
allocated during class loading: dimensions are derived and the zero image is
streamed into the digest. Fixed-column bytes are owned once and read in place.
Verification still consumes CPU and memory proportional to authenticated class
sizes and supplied encodings. Deployments may impose their own resource budgets;
such limits are application policy and can reject inputs upstream accepts.

The `leanvm-claims` CLI subcommand also adds no transport byte cap. The existing `leanvm`
and `sp1` subcommands retain their separately documented limits. CLI input files
are raw upstream encodings; gzip is only fixture storage.

See the repository [security assumptions](../../README.md#security-assumptions-and-limits).
The scalar field code is portable Go.

## Fixtures and provenance

All test inputs ship in this repository; none depends on another workspace or
`.context`. Missing fixtures fail tests.

- `one-tier.key.gz`, `two-tier.key.gz`: **loader-only zero-column derivatives**
  of real Rust setup keys (20/40 MB raw, about 20/40 KB compressed). They test
  loading, not valid circuit proofs. `classes.json` records both setup and
  derivative digests, semantic/structural decisions and placeholder digests.
- `roots/`: genuine upstream `examples/mixed_program_tree.rs` outputs, roots for
  1/2/4 programs. Its 25,282,600-byte class key compresses to 5,214,392 bytes.
- `tiers/`: genuine first-level, small-node and Wide roots from the pinned Rust
  APIs. Its 40,046,448-byte class key compresses to 8,221,924 bytes. First-level
  seal encoding is the canonical empty transcript, eight bytes.
- `forgery/`: the upstream `assert_fake_large_wrap_refused` regression. The fake
  child fails recursion verification; the wrap has a valid recursion proof but
  fails its Wide seal. The helper's arity parameter is generalized from 3 to the
  design's arity (2), so it reuses `tiers/`'s identical authenticated class key.
  No verifier/prover method or upstream assertion is weakened.
- Component JSONs contain Rust transcript/field/wire/Merkle vectors, seven actual
  PCS proofs, three actual flock reductions and their returned claims.
  `matrices.json` has 63 bilinear and 63 flock matrix-form probes;
  `layouts.json` has 50 recursion placements and 99 leaf-size cases.
- `root-components.json` and `tier-verdicts.json` hold full Rust verifier decisions
  for originals and byte flips, truncation, wrong claims/matrices and swapped or
  malformed seals. The public Go API replays every recorded decision.

Each genuine fixture directory has `provenance.json` with the pin, generator and
uncompressed sizes/SHA-256 hashes. `artifacts.json` also inventories compressed
files and generated runtime data. Fixtures retain upstream MIT licensing;
ported flock/PCS attribution and MIT/Apache notices are in `NOTICE` and
`LICENSES/`. Generated circuit/table metadata is about 3 MB, exported from the
pinned source rather than manually transcribed.

## Reproduction

Go verification needs no Rust:

```sh
CGO_ENABLED=0 go test -p 1 ./experimental/leanvmclaims/...
CGO_ENABLED=0 go test -p 1 -tags purego ./experimental/leanvmclaims/...
CGO_ENABLED=1 go test -race -p 1 ./experimental/leanvmclaims/...
python3 tools/check_artifacts.py
```

Regenerate component vectors, metadata, and full Rust decisions on shipped roots
(without proving VM executions again):

```sh
python3 tools/leanvm-mixed/regenerate.py --check
```

Explicit proof generation uses two workers and is more expensive:

```sh
python3 tools/leanvm-mixed/regenerate.py --export-proofs .context/mixed/proofs
python3 tools/leanvm-mixed/pack_proofs.py .context/mixed/proofs --check
python3 tools/leanvm-mixed/generate_tiers.py --check
python3 tools/leanvm-mixed/generate_forgery.py --check
```

Omit `--check` to update packaged outputs. `generate_tiers.py --from-directory DIR`
can package a completed `tier_proofs` Rust run without repeating proving.
Generators use locked Cargo dependencies and the full commit SHA. Metadata and
forgery exporters fetch isolated exact-pin checkouts; original workspaces and
Cargo source checkouts are never edited. Metadata adds inspection methods only;
forgery adjustments are recorded in its manifest.

## Source mapping

| Go | Pinned Rust |
| --- | --- |
| `internal/classkey` | `rec/tree/embed.rs`, `design.rs`, `mixed.rs`, program key digest |
| `internal/machine` | `rec/layout.rs`, `rec/fixed.rs`, `cpu/layout.rs`, flock circuit gates, rec slot/identity forms |
| `internal/transcript`, `internal/blake` | `fiat_shamir` duplex/session/proof/POW |
| `internal/field` | `primitives/field/gf2_64.rs`, `gf2_192.rs` |
| `internal/wire` | `rec/tree/proof.rs`, `multiset.rs` |
| `internal/pcs` | Merkle, WHIR, stacked point/ring openings |
| `internal/flock` | zerocheck, skip domain, deferred lincheck and matrix settlement |
| `internal/recursion` | `gkr/mod.rs`, recursion bus specialization, `constraints.rs`, `rec/proof.rs` |
| `internal/settlement` | `rec/tree/mod.rs`, `statement.rs`, `seal.rs` |
| `verifier.go` | checked mixed class load + `verify_claims_sealed` |

Benchmarks: `go test ./experimental/leanvmclaims -run '^$' -bench 'ClassLoad|VerifySealed' -benchmem`.
See `PERFORMANCE.md` for measured samples and their limitations.
