# leanVM claim-tree reference tools

Cargo.toml, Cargo.lock and common.py pin sm-stack/leanVM to
`fc3fc9ec0ec218d6b5196ecae85a975590729ae6`.

Run `python3 tools/leanvm-mixed/regenerate.py --check` to replay upstream
conformance proofs, regenerate rejection vectors and compare primitive vectors,
WHIR profiles and private machine metadata. Rust is a development dependency;
the Go library and CLI do not invoke it. Build parallelism is limited to two.

`--source PATH` imports conformance files from a local upstream git checkout;
`git archive` reads the exact pin without modifying its working tree.
`--skip-metadata` omits private metadata export. The full source correspondence
and coverage limits are in [PORTING.md](../../experimental/leanvmclaims/PORTING.md).

`benchmark RAW_DIRECTORY` measures loaded-key sealed verification with one Rust
worker. The directory contains class-key.bin and root.bin, claims.bin, seal.bin.
The Go counterpart is `go run ./tools/benchmark-claims -dir RAW_DIRECTORY` and
also needs class-key.digest (32 raw bytes or 64 hexadecimal characters).

After checks, reclaim build outputs with
`cargo clean --manifest-path tools/leanvm-mixed/Cargo.toml`.
