# Experimental leanVM claim-tree verifier

This package verifies sealed roots of program-labelled member sets in the custom
`sm-stack/leanVM` fork. It supports package 0.1.0 at
**`fc3fc9ec0ec218d6b5196ecae85a975590729ae6`**, branch `op-stack/claim-set-leaves`.
It is independent of the standalone `leanvm/` ELF/proof verifier.

## API and trust

```go
v, err := leanvmclaims.NewClassVerifier(classKey, trustedDigest)
if err != nil { return err }
claims, err := leanvmclaims.ClaimsFromStatements(statements)
if err != nil { return err }
return v.VerifySealed(claims, root, seal)
```

The digest must come from trusted application configuration. The constructor
checks `BLAKE2s-256("leanvm/mixed-class-key/v4" || key)`, validates the encoded
configuration and layouts, and retains owned values. `Config()` returns a copy.
Load once and reuse concurrently; caller-owned proof and claim slices must remain
unchanged during verification. Constructor errors wrap `ErrClass`; rejected
proofs wrap `ErrProof`.

The application authorizes program identities and supplies the intended members.
A member is an entry committed by a guest, not necessarily its execution output.
`ClaimsFromStatements` maps a `[32]byte` program digest to four little-endian
uint64 label words followed by two zeros, and the member digest to four words.
Inputs must be canonical and duplicate-free; the function does not sort them.
Canonical order compares unsigned words, not digest bytes. Signature freshness
and replay policies belong to the application.

## Protocol

The only accepted encodings are `LVMXCK04`, `LVMT` version 22, and the framed
`leanvm/mixed-tree-seal/v3` session. Tree sessions use `leanvm-tree-19`.
The [upstream specification](https://github.com/sm-stack/leanVM/blob/fc3fc9ec0ec218d6b5196ecae85a975590729ae6/doc/compact-class-key.md)
defines the exact layout and domain framing.

The class key holds dimensions and commitment roots, with no fixed-column rows.
The seal supplies exactly 102 root column evaluations before PCS challenges.
Verification combines these with the statement contribution to PUB constants,
checks recursion and carried matrix claims, and authenticates every consumed
column against the root tier's commitment. The recorded column claim excludes
the statement contribution. Stable descending column heights determine offsets,
with column index breaking ties.

Each tier has a Boolean usage value. An unused tier must publish a zero fixed
value; used tiers supply a carried fixed-polynomial opening. The root's own 102
columns are always opened, including first-level roots. Seal challenges bind the
entire serialized root's BLAKE2s digest and its statement. Missing or additional
openings and unread message/hint bytes are rejected. There is no sealless path.

A **first-level root** aggregates leaf executions; a **small node** combines
children within the small tier; **wide** denotes the large-capacity tier.
A **wrap** represents a child in another tier. Each ZK leaf class has its own
first-level tier and a LeafWrap back into the small tier. Leaf-proof verification,
proving, circuit construction and same-program trees are outside this package.

The verifier adds no arbitrary byte-size limit. Counts are checked against input
length and authenticated dimensions before allocations. Compact keys remove the
fixed-row allocation and persistent bus scratch cache. `SetScratchCacheLimit`
is a deprecated compatibility no-op (negative inputs still return an error).

## Fixtures and reproducibility

`testdata/compact/` contains deterministic gzip copies of the pinned upstream
`conformance/mixed-class-key-v4/` files, checked against raw SHA-256 hashes in
`provenance.json`. These MIT-licensed leanVM artifacts use the operational class:
capacity `(16385,1024)`, small tier `(257,64)`, two plain classes and one ZK class.
The key is 1,288 bytes and its digest is
`5345ead055078db8baf0dc0db0c605ccd9f32a26c8c7626b3f28d007a3d9d7ee`.

The corpus replays all eight upstream verdicts: four accepted plain/ZK roots,
missing/extra opening, altered tier and wrong digest. Rust-generated component
vectors add root-region flips, truncations, wrong claims, seal mutations, and
reauthenticated class changes. Separate Go component tests isolate native EOF,
HASH matrix binding, tier dispatch, seal session/root hash, column count, Boolean
usage and zero unused values. Primitive, layout and matrix vectors are also
regenerated from the same pin. Missing fixtures fail tests.

The independent seven-statement Optimism aggregate has not been supplied at this
pin. The current corpus does not replace every old forged-prover scenario or
provide a positive one-tier/all-ZK class. A changed root-proof byte with the same
statement tests hash binding; this is not a second valid randomized proof of that
statement. These are coverage gaps, not demonstrated acceptance differences.
Security assumptions and the limits of finite differential testing are in the
repository README.

```sh
CGO_ENABLED=0 GOMAXPROCS=2 go test -p 1 ./...
CGO_ENABLED=0 GOMAXPROCS=2 go test -p 1 -tags purego ./...
CGO_ENABLED=1 GOMAXPROCS=2 go test -race -p 1 ./...
python3 tools/leanvm-mixed/regenerate.py --check
python3 tools/check_guards.py
python3 tools/check_artifacts.py
```

The regeneration command imports fixtures from the exact upstream commit and
replays existing proofs; it does not generate leaf proofs. It also exports private
machine metadata in an isolated checkout. `--source PATH` reads fixtures through
`git archive` from an existing checkout; it never modifies that checkout.
`--skip-metadata` runs only vector replay; metadata can be checked separately with
`tools/leanvm-mixed/export_metadata.py --check`.

## Source correspondence

| Go | Pinned Rust |
| --- | --- |
| `internal/classkey` | `rec/tree/{embed,design,mod}.rs` |
| `internal/wire` | `rec/tree/{proof,claims}.rs` |
| `internal/recursion` | `rec/proof.rs`, `bus/`, `constraints/` |
| `internal/settlement` | `rec/tree/{seal,statement,mod}.rs` |
| `internal/flock` | `crates/flock/src/` |
| `internal/pcs` | `crates/pcs/src/`, `stacking.rs` |
| `internal/transcript` | `crates/fiat_shamir/src/` |
| `internal/field`, `internal/gf2` | `crates/primitives/src/field/` |

Licenses and inherited notices are listed in `NOTICE` and `LICENSES/`.
