#!/usr/bin/env python3
"""Ensure focused regressions fail when selected security checks are disabled.
Uses Go overlays in a temporary directory; never modifies the working tree.
This finite mutation suite is not a proof that every check is independently covered.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
CASES = [
    ('jagged.go', 'checkedPrefixSum >= 1<<30', 'TestJaggedTotalAreaBound'),
    ('verifier.go', 'hashFelts(pv[:pvNumHashed]) != digest(pv[pvDigest:pvDigest+digestSize])', 'TestCompressedBindings'),
    ('verifier.go', 'digest(pv[pvVkRoot:pvVkRoot+digestSize]) != vkMerkleRoot', 'TestCompressedBindings'),
    ('verifier.go', 'pv[pvIsComplete] != 1', 'TestCompressedBindings'),
    ('verifier.go', 'digest(pv[pvSP1VkDigest:pvSP1VkDigest+digestSize]) != vkey', 'TestCompressedBindings'),
    ('decode.go', '!found && len(out) == maxChips', 'TestMapLimits'),
    ('decode.go', 'len(k) > maxChipNameBytes', 'TestMapLimits'),
    ('shard.go', 'numeratorEval != mleEval(numerators, interactionPoint)', 'TestGKRStageBindings'),
    ('shard.go', 'z.claimedSum != modification', 'TestZerocheckStageBindings'),
    ('jagged.go', 'rc[n-2][1]+1 != addedColumns[round] || rc[n-1][1] != 1 || rc[n-2][0] != maxRowCount ||\n\t\t\trc[n-1][0] != addedValues[round]-(addedColumns[round]-1)*maxRowCount', 'TestJaggedPaddingRows'),
    ('pcs.go', 'index != 0', 'TestMerkleIndexBound'),
    ('decode.go', '!utf8.Valid(b)', 'TestDecodeResourceGuards'),
    ('decode.go', 'numDims > 3', 'TestDecodeResourceGuards'),
    ('decode.go', '!ok', 'TestDecodeResourceGuards'),
    ('decode.go', 'len(b) > maxProofBytes', 'TestDecodeResourceGuards'),
    ('shard.go', 'd.isZero()', 'TestGKRZeroDenominator'),
]
env = dict(os.environ, CGO_ENABLED='0', GOMAXPROCS='2', PWD=str(ROOT))

def check_mutation(original, old, new, package, test):
    text = original.read_text()
    if text.count(old) != 1:
        raise SystemExit(f'expected exactly one mutation site: {original}: {old}')
    with tempfile.TemporaryDirectory(prefix='stark-guard-') as tmp:
        tmp = Path(tmp)
        modified = tmp/original.name
        modified.write_text(text.replace(old, new))
        overlay = tmp/'overlay.json'
        overlay.write_text(json.dumps({'Replace': {str(original): str(modified)}}))
        proc = subprocess.run(['go', 'test', '-p', '1', '-count=1', '-overlay', str(overlay),
                               package, '-run', '^'+test+'$'], cwd=ROOT, env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if proc.returncode == 0 or '--- FAIL:' not in proc.stdout:
            print(proc.stdout)
            raise SystemExit(f'mutation survived or failed to build: {original}: {old}')
    print(f'caught {original.name}: {old.splitlines()[0]}', flush=True)

CLAIMS = 'experimental/leanvmclaims/internal/'
MIXED_CASES = [
 ('recursion/arith.go', 'if expected != claim {', 'if false && expected != claim {', 'recursion', 'TestGKRLayerBindings'),
 ('recursion/arith.go', 'if prods[0].Add(lambda.Mul(prods[1])) != claim {', 'if false && prods[0].Add(lambda.Mul(prods[1])) != claim {', 'recursion', 'TestGKRLayerBindings'),
 ('flock/reduction.go', 'if terminal != claim {', 'if false && terminal != claim {', 'flock', 'TestZerocheckTerminalBinding'),
 ('transcript/verifier.go', 'return v.fail(ErrPOW)', 'return nil', 'transcript', 'TestPOWBinding'),
 ('pcs/merkle.go', 'return nil, v.InvalidHint()', 'return nil, nil', 'pcs', 'TestReadRowsAuthentication'),
 ('recursion/verify.go', 'if err = v.EOF(); err != nil {', 'if false {', 'recursion', 'TestRootEOFBinding'),
 ('recursion/verify.go', 'return replay[0].Matrix.Check(hash, make([]E, len(hash.Gates)))', 'return nil', 'recursion', 'TestHashMatrixBinding'),
 ('recursion/verify.go', 'layout := k.Layouts[tier]', 'layout := k.Layouts[tier%1]', 'recursion', 'TestTierLayoutSelection'),
 ('recursion/verify.go', 'tier := k.Places[position].Tier', 'tier := 1', 'recursion', 'TestTierLayoutSelection'),
]
# Every entry uses (source, replacement site, replacement, package, regression).
mutations = [('sp1/'+file, 'if '+condition+' {', 'if false && ('+condition+') {', './sp1', test)
             for file, condition, test in CASES]
mutations += [
    ('leanvm/elf.go', 'if segments[i-1].end > segments[i].start {',
     'if false && segments[i-1].end > segments[i].start {', './leanvm', 'TestRejectOverlappingSegmentsBeforeCopy'),
    ('leanvm/elf.go', 'tableKey{strOffset, strSize, offset % entsize}',
     'tableKey{0, 0, offset % entsize}', './leanvm', 'TestSymbolCacheSeparatesStrings'),
]
mutations += [(CLAIMS+file, old, new, './'+CLAIMS+package, test)
              for file, old, new, package, test in MIXED_CASES]
mutations += [
 ('experimental/leanvmclaims/internal/settlement/settlement.go', 'if !k.Places[position].First {', 'if position >= len(k.Config.Leaves) {', './experimental/leanvmclaims', 'TestZKRoots'),
 ('experimental/leanvmclaims/internal/classkey/semantic.go', 'tag = append(tag, byte(leaf.Kind))', 'tag = append(tag, byte(leaf.Kind)*0)', './experimental/leanvmclaims', 'TestZKRoots'),
 ('experimental/leanvmclaims/internal/classkey/key.go', 'if r.word() != 1 {', 'if r.word() > 1 {', './experimental/leanvmclaims', 'TestZKContainer'),
 ('experimental/leanvmclaims/internal/recursion/verify.go', 'tier := k.Places[position].Tier', 'tier := min(k.Places[position].Tier, 1)', './experimental/leanvmclaims', 'TestZKRoots'),
 ('experimental/leanvmclaims/internal/settlement/settlement.go', ' || uint64(root.Rate) != k.Config.TreeRate', '', './experimental/leanvmclaims', 'TestRootRateBinding'),
]
mutations += [
 ('experimental/leanvmclaims/internal/classkey/key.go', ' || config.check() != nil', '', './experimental/leanvmclaims', 'TestClassContainerGuards'),
 ('experimental/leanvmclaims/internal/classkey/semantic.go', ' || leaf.MaxMembers == 0', '', './experimental/leanvmclaims', 'TestClassContainerGuards'),
 ('experimental/leanvmclaims/internal/classkey/semantic.go', 's := c.Small; s != nil &&', 's := c.Small; false && s != nil &&', './experimental/leanvmclaims', 'TestClassContainerGuards'),
 ('experimental/leanvmclaims/internal/classkey/semantic.go', 'for _, c := range config.Leaves {', 'for _, c := range config.Leaves[:1] {', './experimental/leanvmclaims', 'TestAuthenticatedClassMutations'),
 ('experimental/leanvmclaims/internal/classkey/key.go', ' || n != expectedCircuits', ' || (false && n != expectedCircuits)', './experimental/leanvmclaims', 'TestClassContainerGuards'),
 ('experimental/leanvmclaims/internal/classkey/key.go', 'c.Heights != k.Heights[tier]', '(false && c.Heights != k.Heights[tier])', './experimental/leanvmclaims', 'TestClassContainerGuards'),
]
mutations += [
 ('experimental/leanvmclaims/internal/classkey/semantic.go', 'tag = append(tag, byte(leaf.LeafRate))', 'tag = append(tag, byte(first.LeafRate))', './experimental/leanvmclaims', 'TestRustOneTierVerdicts'),
 ('experimental/leanvmclaims/internal/classkey/key.go', ' || n > uint64(len(data)-r.pos)/880', '', './experimental/leanvmclaims', 'TestRejectBeforeLargeAllocation'),
 ('experimental/leanvmclaims/internal/wire/proof.go', ' || (statementWords >= 0 && n != uint64(statementWords))', '', './experimental/leanvmclaims', 'TestRejectBeforeLargeAllocation'),
 ('experimental/leanvmclaims/claims.go', 'if err := claims.Check(math.MaxUint64, math.MaxUint32); err != nil {', 'if err := claims.Check(math.MaxUint64, math.MaxUint32); false && err != nil {', './experimental/leanvmclaims', 'TestEncodeClaimsCanonical'),
 ('experimental/leanvmclaims/verifier.go', 'if v == nil || v.class == nil {\n\t\treturn ErrClass', 'if false {\n\t\treturn ErrClass', './experimental/leanvmclaims', 'TestNilVerifier'),
]
# A pre-existing failing regression must never count as a caught mutation.
for package in sorted({case[3] for case in mutations}):
    tests = sorted({case[4] for case in mutations if case[3] == package})
    subprocess.run(['go', 'test', '-p', '1', '-count=1', package,
                    '-run', '^('+'|'.join(tests)+')$'], cwd=ROOT, env=env, check=True)
for file, old, new, package, test in mutations:
    check_mutation(ROOT/file, old, new, package, test)
print(f'caught all {len(mutations)} guard mutations')
