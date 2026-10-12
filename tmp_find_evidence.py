import json
from pathlib import Path

# Search for 64-position differential evidence
for d in Path(r'F:/rawrxd/evidence').rglob('*'):
    if d.is_dir() and '64' in d.name:
        print(f'64pos: {d}')
        manifest = d / 'manifest.json'
        if manifest.exists():
            m = json.loads(manifest.read_text())
            positions = sorted(set(e.get('position') for e in m if 'position' in e))
            print(f'  Positions: {positions[:3]}...{positions[-3:] if len(positions) > 3 else positions}, count={len(positions)}')

# Look for certificate files
for d in Path(r'F:/rawrxd/evidence').rglob('*'):
    if d.is_file() and ('cert' in d.name.lower() or '64' in d.name):
        print(f'Cert file: {d}')

# Check ref_capture_repro
ref_repro = Path(r'F:/rawrxd/evidence/RAWRXD_REFERENCE_REPRODUCIBILITY_001')
print(f'\nRAWRXD_REFERENCE_REPRODUCIBILITY_001 contents:')
for item in sorted(ref_repro.iterdir()):
    print(f'  {item.relative_to(ref_repro)}')
