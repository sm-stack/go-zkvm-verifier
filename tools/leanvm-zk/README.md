# ZK claim-tree reference tools

Pinned to sm-stack/leanVM `3e269bd4137976648052a3335845d0c19693ec0d`
(`op-stack/claim-set-leaves`, package 0.1.0). These are development tools only.
The Go runtime does not link Rust or verify leaf proofs.

```sh
# Replay genuine proofs and rehashed class mutations; compare saved verdicts.
# Also rebuild the operational v2/v3 class keys and compare every byte.
python3 tools/leanvm-zk/check.py

# Generate the small plain/plain/ZK corpus, including the raw ZK First root.
# SOURCE is any git checkout containing the pinned commit. Only WORK is modified.
python3 tools/leanvm-zk/export_raw.py SOURCE WORK
python3 tools/leanvm-zk/package.py WORK/proofs

# All-ZK class, without the optional small/large tier split.
cargo run --locked --release -j 2 --manifest-path tools/leanvm-zk/Cargo.toml \
  --bin zk_proofs -- WORK/zk-only --one-tier --zk-only
python3 tools/leanvm-zk/package.py WORK/zk-only --name zk-only

# Rebuild operational keys and extract archived aggregate payloads.
cargo run --locked --release -j 2 --manifest-path tools/leanvm-zk/Cargo.toml \
  --bin production -- WORK/production
python3 tools/leanvm-zk/package.py WORK/production --production
```

Use two workers for generation. `export_raw.py` archives the exact commit into a
fresh directory and adds a serialization hook immediately before automatic
LeafWrap. It runs the unchanged Rust verifier on that raw First root and asserts
that the same proof is rejected as a node child. The hook does not alter circuit
construction, proof arithmetic or verifier acceptance. Both original and loaded
verifiers are exercised; `check.py` replays with the unmodified upstream dependency.

ZK proving uses upstream's normal randomness. Regenerated proof bytes may differ;
regenerate their verdicts with `root_components` and `key_vectors`, then update
`artifacts.json`. Class keys and digests are deterministic. Required Go tests
replay the committed gzip fixtures without invoking Rust or accessing a local
workspace. Each fixture manifest records its generating revision and SHA-256 of
the uncompressed bytes. Missing or corrupt fixtures fail tests.

`production/` contains MIT-licensed Optimism source and payload snapshots. Its
manifest identifies the v2 committed revision and the v3 working-tree source by
hash; it does not represent the v3 integration as an upstream commit. The keys
are built here, and the archived payloads supply the existing root/claim/seal
bytes without leaf proving. The RLP adapter is used only by this tooling.
Reproducing those guest executions requires the corresponding Optimism setup.

The earlier v2 corpus and its original generators remain at their generating
revision under `tools/leanvm-mixed/`. `check.py` also replays its full-root verdicts
with the new Rust verifier. VM matrix metadata and PCS profiles are unchanged
between those revisions. The shared descriptor adapter supports both formats.

After use, reclaim build output with:

```sh
cargo clean --manifest-path tools/leanvm-zk/Cargo.toml
```
