from pathlib import Path
import re
import struct

# Check ref_64 logits step
ref_64 = Path(r'F:/rawrxd/evidence/RAWRXD_REFERENCE_REPRODUCIBILITY_001/ref_64')
logits_files = sorted(ref_64.glob('logits*'))
print(f'ref_64 logits files: {len(logits_files)}')
for f in logits_files[:10]:
    print(f'  {f.name} ({f.stat().st_size} bytes)')

# Check ref_A naming pattern
ref_A = Path(r'F:/rawrxd/evidence/RAWRXD_REFERENCE_REPRODUCIBILITY_001/ref_A')
bins_A = sorted(ref_A.glob('*.bin'))
print(f'\nref_A first 20 files:')
for f in bins_A[:20]:
    print(f'  {f.name}')

# Check if steps have different numbers
steps_A = set()
for f in bins_A:
    m = re.match(r'probe_(.+?)_l(\d+)_', f.name)
    if m:
        steps_A.add(m.group(1))
sorted_steps_A = sorted(steps_A)
print(f'\nref_A step patterns: {sorted_steps_A[:10]}')

# Check ref_B
ref_B = Path(r'F:/rawrxd/evidence/RAWRXD_REFERENCE_REPRODUCIBILITY_001/ref_B')
bins_B = sorted(ref_B.glob('*.bin'))
print(f'\nref_B first 20 files:')
for f in bins_B[:20]:
    print(f'  {f.name}')

# Check the file format
print('\n--- Checking file format ---')
with open(bins_A[0], 'rb') as f:
    header = f.read(64)
    print(f'File: {bins_A[0].name}')
    print(f'Header (hex): {header[:16].hex()}')
    # Try reading shape
    f.seek(0)
    f.read(4)  # magic
    shape_len = int.from_bytes(f.read(4), 'little')
    print(f'Shape dim count: {shape_len}')
    shape = []
    for _ in range(shape_len):
        shape.append(int.from_bytes(f.read(8), 'little'))
    print(f'Shape: {shape}')
    total_elements = 1
    for s in shape:
        total_elements *= s
    print(f'Total elements: {total_elements}')
    remaining = f.read()
    print(f'Data size: {len(remaining)} bytes = {len(remaining)/4} float32')
