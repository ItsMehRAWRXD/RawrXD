#!/usr/bin/env python3
"""Standard library only. Compare two matching IR activation dump directories."""
import argparse, math, struct
from pathlib import Path

def read(path):
    b=path.read_bytes()
    if len(b)%4: raise ValueError(f'{path}: not float32 bytes')
    return struct.unpack('<'+str(len(b)//4)+'f',b)

p=argparse.ArgumentParser()
p.add_argument('actual',type=Path)
p.add_argument('reference',type=Path,nargs='?')
p.add_argument('--atol',type=float,default=1e-4)
p.add_argument('--rtol',type=float,default=1e-4)
a=p.parse_args()
filenames=sorted(a.actual.glob('op_*.bin'))
if not filenames: raise SystemExit('NO_ACTIVATION_DUMPS')
print('OP COUNT NONFINITE MIN MAX L2 '+('RMSE MAX_ABS MAX_IDX BAD_COUNT' if a.reference else ''))
first_bad=None
for f in filenames:
    x=read(f);finite=[v for v in x if math.isfinite(v)]
    stats=[f.stem,len(x),len(x)-len(finite),
        f'{min(finite):.7g}' if finite else 'nan',
        f'{max(finite):.7g}' if finite else 'nan',
        f'{math.sqrt(math.fsum(v*v for v in finite)):.7g}' if finite else 'nan']
    if a.reference:
        other=a.reference/f.name
        if not other.is_file():
            print(*stats,'REFERENCE_MISSING');first_bad=first_bad or f.stem;continue
        y=read(other)
        if len(x)!=len(y):
            print(*stats,f'SHAPE_MISMATCH_REF={len(y)}');first_bad=first_bad or f.stem;continue
        errs=[abs(u-v) for u,v in zip(x,y)]
        bad=sum((not math.isfinite(u) or not math.isfinite(v) or e>a.atol+a.rtol*abs(v))
                for u,v,e in zip(x,y,errs))
        idx=max(range(len(errs)),key=errs.__getitem__) if errs else 0
        rms=math.sqrt(math.fsum(e*e for e in errs)/len(errs)) if errs else 0
        stats.extend([f'{rms:.7g}',f'{errs[idx]:.7g}',idx,bad])
        if bad and first_bad is None:first_bad=f.stem
    print(*stats)
if a.reference:
    print('FIRST_DIVERGENT_OP='+str(first_bad or 'NONE'))
    if first_bad is not None: raise SystemExit(1)
else:
    print('REFERENCE_NOT_SUPPLIED=1; only health statistics available, not numerical parity')
