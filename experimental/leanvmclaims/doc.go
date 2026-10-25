// Package leanvmclaims is an experimental verifier for sealed claim-tree roots
// aggregating execution claims from multiple programs in the sm-stack leanVM fork.
// It verifies the pinned mixed-tree protocol in Go without
// Rust or CGO at UpstreamCommit. A trusted class-key digest and complete expected
// class configuration are required. Class keys are loaded once and can be shared
// by concurrent verifications. The verifier checks roots, not leaf proofs.
//
// This package implements a different pinned protocol from the standalone leanvm
// package. Their transcripts and proof encodings are not interchangeable.
// See PORTING.md for provenance and coverage, and the repository README for
// security assumptions.
package leanvmclaims
