from pathlib import Path
import struct

# Check the format of ref_capture_repro files (which should be in native format)
ref_dir = Path(r'F:/rawrxd/evidence/RAWRXD_REFERENCE_REPRODUCIBILITY_001/ref_capture_repro')
test_file = sorted(ref_dir.glob('*.bin'))[0]
print(f'Test file: {test_file.name}, size: {test_file.stat().st_size}')

with open(test_file, 'rb') as f:
    # Read first 64 bytes
    header = f.read(64)
    print(f'Header bytes: {header[:32].hex()}')
    
    # Try interpretation 1: magic(4) + ndim(4) + shape(ndim*8) + padding(8) + data
    f.seek(0)
    magic = f.read(4)
    print(f'Magic: {magic}')
    ndim = int.from_bytes(f.read(4), 'little')
    print(f'ndim (int32 LE): {ndim}')
    if ndim > 0 and ndim < 10:
        shape = []
        for _ in range(ndim):
            s = int.from_bytes(f.read(8), 'little')
            shape.append(s)
        print(f'Shape: {shape}')
        padding = f.read(8)
        print(f'Padding: {padding.hex()}')
        data_start = f.tell()
        remaining = f.read()
        print(f'Data size: {len(remaining)} bytes = {len(remaining)//4} float32')
        total_elements = 1
        for s in shape:
            total_elements *= s
        print(f'Expected elements: {total_elements}')
    
    # Also try the ref_64 format
    ref_64 = Path(r'F:/rawrxd/evidence/RAWRXD_REFERENCE_REPRODUCIBILITY_001/ref_64')
    test_file_64 = sorted(ref_64.glob('*.bin'))[0]
    print(f'\n--- ref_64 format ---')
    print(f'Test file: {test_file_64.name}, size: {test_file_64.stat().st_size}')
    
    # Compare with a known ref_capture_repro file
    with open(test_file_64, 'rb') as f2:
        header64 = f2.read(64)
        print(f'Header bytes: {header64[:32].hex()}')
        
    # Also check a differential file format
    diff_dir = Path(r'F:/rawrxd/evidence/NUGVERSE_ESTIMATOR_001/differential_fixed')
    test_diff = sorted(diff_dir.glob('*.bin'))[0]
    print(f'\n--- differential_fixed format ---')
    print(f'Test file: {test_diff.name}, size: {test_diff.stat().st_size}')
    with open(test_diff, 'rb') as f3:
        header_diff = f3.read(64)
        print(f'Header bytes: {header_diff[:32].hex()}')
        f3.seek(0)
        magic_diff = f3.read(4)
        ndim_diff = int.from_bytes(f3.read(4), 'little')
        print(f'Magic: {magic_diff}, ndim: {ndim_diff}')
        if ndim_diff > 0 and ndim_diff < 10:
            shape_diff = []
            for _ in range(ndim_diff):
                shape_diff.append(int.from_bytes(f3.read(8), 'little'))
            print(f'Shape: {shape_diff}')
            padding_diff = f3.read(8)
            print(f'Padding: {padding_diff.hex()}')
            data_start_diff = f3.tell()
            remaining_diff = f3.read()
            print(f'Data size: {len(remaining_diff)} bytes = {len(remaining_diff)//4} float32')
