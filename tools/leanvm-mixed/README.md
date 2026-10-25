# Claim-tree reference tools

The guard mutation suite covers GKR odd/radix-4 checks, zerocheck terminal,
PoW, Merkle hint authentication, root transcript exhaustion, terminal HASH
matrix checking and both tier-selection branches. Tier dispatch tests alter
only the unused derived layout of an existing fixture; they do not constitute
a new upstream proof fixture with unequal tier heights.


Run `python3 tools/check_guards.py` from the repository root.
The transcript builders in `internal/testutil` construct targeted negative
inputs; genuine proof fixtures are generated only by the pinned Rust tools.

Reference generators pin their dependencies in `Cargo.toml`/`Cargo.lock` and fetch the same exact revision for private Rust inspection. `regenerate.py --check` compares component vectors, metadata and 240 complete root decisions. `generate_forgery.py` and `generate_attacks.py` retain upstream attack assertions and export their artifacts. Proof generation commands and the Go/Rust source map are in [PORTING.md](../../experimental/leanvmclaims/PORTING.md).

`generate_production.py DIR` produces the uncommitted benchmark class and 357-claim root. `src/bin/benchmark.rs` measures checked load, direct and sealed verification with one worker. `tools/benchmark-claims` measures the Go public API and allocations on those same files. See [PERFORMANCE.md](../../PERFORMANCE.md) for timing and peak-process-memory commands.
