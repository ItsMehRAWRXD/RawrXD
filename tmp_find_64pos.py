import json
from pathlib import Path
import numpy as np

# The 64-position reference from RAWRXD_REFERENCE_REPRODUCIBILITY_001
ref_root = Path(r'F:/rawrxd/evidence/RAWRXD_REFERENCE_REPRODUCIBILITY_001')

# Check ref_64 directory
ref_64 = ref_root / 'ref_64'
if ref_64.exists():
    files = list(ref_64.rglob('*'))
    bin_files = [f for f in files if f.suffix == '.bin']
    txt_files = [f for f in files if f.suffix == '.txt']
    print(f'ref_64: {len(bin_files)} bin files, {len(txt_files)} txt files')
    for f in sorted(bin_files)[:10]:
        print(f'  {f.relative_to(ref_64)}')
    for f in sorted(txt_files):
        print(f'  {f.relative_to(ref_64)}')

# Check ref_capture_repro
ref_repro = ref_root / 'ref_capture_repro'
if ref_repro.exists():
    files = list(ref_repro.rglob('*'))
    bin_files = [f for f in files if f.suffix == '.bin']
    print(f'\nref_capture_repro: {len(bin_files)} bin files')
    for f in sorted(bin_files)[:10]:
        print(f'  {f.relative_to(ref_repro)}')

# Check ref_A, ref_B
for ref_dir in ['ref_A', 'ref_B', 'run1', 'run2', 'stored_reference_backup']:
    d = ref_root / ref_dir
    if d.exists():
        files = list(d.rglob('*'))
        bin_files = [f for f in files if f.suffix == '.bin']
        txt_files = [f for f in files if f.suffix == '.txt']
        print(f'\n{ref_dir}: {len(bin_files)} bin, {len(txt_files)} txt')
        for f in sorted(txt_files):
            print(f'  {f.relative_to(d)}')
