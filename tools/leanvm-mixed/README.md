# Claim-tree reference tools

The guard mutation suite covers GKR odd/radix-4 checks, zerocheck terminal,
PoW, Merkle hint authentication, root transcript exhaustion, terminal HASH
matrix checking and both tier-selection branches. Tier dispatch tests alter
only the unused derived layout of an existing fixture; they do not constitute
a new upstream proof fixture with unequal tier heights.


Run `python3 tools/check_guards.py` from the repository root.
The transcript builders in `internal/testutil` construct targeted negative
inputs; genuine proof fixtures are generated only by the pinned Rust tools.
