#!/usr/bin/env python3
"""Replay the pinned Rust verifier and regenerate deterministic component vectors."""
import argparse
import gzip
import json
from pathlib import Path
import sys
import tempfile
from common import ROOT, PIN, run, checkout
p=argparse.ArgumentParser()
p.add_argument('--check',action='store_true')
p.add_argument('--source',type=Path,help='read-only upstream checkout containing the exact pin')
p.add_argument('--skip-metadata',action='store_true',help='replay vectors only; run export_metadata.py separately')
a=p.parse_args()
target=ROOT/'experimental/leanvmclaims/testdata'
manifest=ROOT/'tools/leanvm-mixed/Cargo.toml'
def cargo(binary,*args):
 run(['cargo','run','--locked','--release','-j','2','--manifest-path',str(manifest),'--bin',binary,'--',*map(str,args)],cwd=ROOT)
with tempfile.TemporaryDirectory(prefix='compact-vectors-') as temp:
 work=Path(temp); source=a.source
 if source is None:
  source=work/'source';checkout(source)
 # git archive resolves the requested commit even when the supplied checkout is on another branch.
 archive=run(['git','-C',str(source),'archive',PIN,'conformance/mixed-class-key-v4'],capture_output=True).stdout
 import io,tarfile,hashlib
 with tarfile.open(fileobj=io.BytesIO(archive)) as t:t.extractall(work,filter='data')
 raw=work/'conformance/mixed-class-key-v4'
 m={'upstream_commit':PIN,'files':{}}
 for f in sorted(raw.rglob('*')):
  if not f.is_file():continue
  name=str(f.relative_to(raw));b=f.read_bytes();m['files'][name]={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
  dest=target/'compact'/(name+'.gz')
  if a.check:
   if gzip.decompress(dest.read_bytes())!=b:raise SystemExit(f'upstream fixture differs: {name}')
  else:dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(gzip.compress(b,mtime=0))
 path=target/'compact/provenance.json'
 if a.check:
  if json.loads(path.read_text())!=m:raise SystemExit('fixture manifest differs')
 else:path.write_text(json.dumps(m,indent=2)+'\n')
 outputs=[]
 for name in ['transcript','wire','field','merkle','whir','stack','flock','statements']:
  cargo(name,work/(name+'.json'));outputs.append(name+'.json')
 for binary,name in [('root_components','compact-components.json'),('class_mutations','compact-class-mutations.json')]:
  cargo(binary,target/'compact',work/name);outputs.append(name)
 cargo('leanvm-mixed-reference',raw,work/'compact-mutations.json');outputs.append('compact-mutations.json')
 for name in outputs:
  b=(work/name).read_bytes();dest=target/name
  if a.check:
   if dest.read_bytes()!=b:raise SystemExit(f'Rust output differs: {name}')
   print('matched:',name)
  else:dest.write_bytes(b)
 cargo('config',work/'config_table_gen.go');run(['gofmt','-w',str(work/'config_table_gen.go')])
 dest=ROOT/'experimental/leanvmclaims/internal/pcs/config_table_gen.go';b=(work/'config_table_gen.go').read_bytes()
 if a.check:
  if dest.read_bytes()!=b:raise SystemExit('WHIR profile differs')
 else:dest.write_bytes(b)
if not a.skip_metadata:run([sys.executable,str(ROOT/'tools/leanvm-mixed/export_metadata.py'),*(['--check'] if a.check else [])],cwd=ROOT)
