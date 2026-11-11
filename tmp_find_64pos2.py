from pathlib import Path
import re

ref_repro = Path(r'F:/rawrxd/evidence/RAWRXD_REFERENCE_REPRODUCIBILITY_001/ref_capture_repro')
bins = sorted(ref_repro.glob('*.bin'))

layers = set()
positions = set()
for f in bins:
    m = re.match(r'ref_l(\d+)_p(\d+)_(.+)', f.name)
    if m:
        layers.add(int(m.group(1)))
        positions.add(int(m.group(2)))

sorted_layers = sorted(layers)
sorted_positions = sorted(positions)
print(f'ref_capture_repro: {len(bins)} files')
print(f'Layers: {sorted_layers[:5]}...{sorted_layers[-5:] if len(sorted_layers)>5 else sorted_layers}')
print(f'Positions: {sorted_positions[:5]}...{sorted_positions[-5:] if len(sorted_positions)>5 else sorted_positions}')

# Check tensor types
tensor_types = set()
for f in bins:
    m = re.match(r'ref_l\d+_p\d+_(.+)', f.name)
    if m:
        tensor_types.add(m.group(1))
print(f'Tensor types: {sorted(tensor_types)}')

# Check ref_64 format
ref_64 = Path(r'F:/rawrxd/evidence/RAWRXD_REFERENCE_REPRODUCIBILITY_001/ref_64')
bins64 = sorted(ref_64.glob('*.bin'))
print(f'\nref_64: {len(bins64)} files')
steps = sorted(set(f.name.split('_')[1] for f in bins64))
print(f'Steps: {steps[:10]}...{steps[-5:] if len(steps)>5 else steps}')
print(f'Step count: {len(steps)}')

# Check tensor naming for step 0
step0 = sorted(ref_64.glob('probe_step00_*'))
print(f'\nStep 0 files ({len(step0)}):')
for f in step0[:10]:
    print(f'  {f.name}')
