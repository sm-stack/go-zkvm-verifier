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

# A pre-existing failing regression must never count as a caught mutation.
baseline = sorted({test for _, _, test in CASES} | {'TestRejectOverlappingSegmentsBeforeCopy', 'TestSymbolCacheSeparatesStrings'})
subprocess.run(['go', 'test', '-p', '1', '-count=1', './sp1', './leanvm',
                '-run', '^('+'|'.join(baseline)+')$'], cwd=ROOT, env=env, check=True)

for file, condition, test in CASES:
    check_mutation(ROOT/'sp1'/file, 'if '+condition+' {', 'if false && ('+condition+') {', './sp1', test)
check_mutation(ROOT/'leanvm/elf.go', 'if segments[i-1].end > segments[i].start {',
               'if false && segments[i-1].end > segments[i].start {', './leanvm', 'TestRejectOverlappingSegmentsBeforeCopy')
check_mutation(ROOT/'leanvm/elf.go', 'tableKey{strOffset, strSize, offset % entsize}',
               'tableKey{0, 0, offset % entsize}', './leanvm', 'TestSymbolCacheSeparatesStrings')
print(f'caught all {len(CASES)+2} guard mutations')
