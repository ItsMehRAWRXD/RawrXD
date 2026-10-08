#!/usr/bin/env python3
"""Fail-closed injection into local IR executor; preserves a .before_parity_trace.bak backup."""
import argparse
from pathlib import Path
import re

ap=argparse.ArgumentParser()
ap.add_argument('executor',type=Path)
ap.add_argument('--apply',action='store_true')
a=ap.parse_args()
s=a.executor.read_text(encoding='utf-8-sig')
if 'RAWRXD_PARITY_TRACE_INJECTED' in s:
    raise SystemExit('ALREADY_INSTRUMENTED: refuse duplicate injection')
if not re.search(r'\bclass\s+IRExecutor\b',s):
    raise SystemExit('NO_IR_EXECUTOR: no changes made')
if not re.search(r'\barena_\.Size\s*\(',s) and not re.search(r'\bsize_t\s+Size\s*\(',s):
    raise SystemExit('NO_ARENA_SIZE_API: add Size(id) to ActivationArena first; no changes made')
inc = '#include "RawrXD_IR_Trace.hpp" // RAWRXD_PARITY_TRACE_INJECTED\n'
pos=s.find('#include ')
if pos<0: raise SystemExit('NO_INCLUDE_ANCHOR: no changes made')
s=s[:pos]+inc+s[pos:]
# A call after Dispatch within the IRExecutor loop, before if(executed) accounting.
pattern=r'(\bbool\s+executed\s*=\s*PrimitiveDispatcher::Dispatch\([^;]+\);)'
hits=list(re.finditer(pattern,s,re.DOTALL))
if len(hits)!=1: raise SystemExit(f'DISPATCH_ANCHOR_COUNT={len(hits)}: no changes made')
insert='''\n            if (executed && op.output.domain == MG::OperandDomain::Activation) {
                RawrXD_IR_Trace::save(op.opId, arena_.Get(op.output.id),
                                     arena_.Size(op.output.id));
            }
'''
s=s[:hits[0].end()]+insert+s[hits[0].end():]
if a.apply:
    backup=a.executor.with_suffix(a.executor.suffix+'.before_parity_trace.bak')
    if backup.exists(): raise SystemExit('BACKUP_EXISTS: no changes made; protect original')
    backup.write_bytes(a.executor.read_bytes())
    a.executor.write_text(s,encoding='utf-8')
    print(f'PATCH_APPLIED=1 BACKUP={backup}')
else:
    print('DRY_RUN=PASS PATCH_APPLIED=0; use --apply to write backup and instrument')
