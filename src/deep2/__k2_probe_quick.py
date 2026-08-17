#!/usr/bin/env python3
"""Quick probe: read first 20 tensor records with boundary validation."""
import struct
import sys
import os

def read_u32(f): return struct.unpack('<I', f.read(4))[0]
def read_u64(f): return struct.unpack('<Q', f.read(8))[0]
def read_str(f):
    l = read_u64(f)
    return f.read(l).decode('utf-8', errors='replace') if l else ""

def skip_value(f, vt):
    if vt == 0: f.read(1)
    elif vt in (1,2,3,4,5,6,7): f.read({0:1,1:1,2:2,3:2,4:4,5:4,6:4,7:1}[vt])
    elif vt == 8: read_str(f)
    elif vt == 9:
        at, al = read_u32(f), read_u64(f)
        for _ in range(al): skip_value(f, at)
    elif vt in (10,11): f.read(8)
    elif vt == 12: f.read(8)

path = sys.argv[1]
file_size = os.path.getsize(path)

with open(path, 'rb') as f:
    magic = f.read(4)
    version = read_u32(f)
    n_tensors = read_u64(f)
    n_metadata = read_u64(f)
    
    print(f"File: {path}")
    print(f"Size: {file_size:,} bytes ({file_size/1024/1024/1024:.2f} GB)")
    print(f"Version: {version}, Tensors: {n_tensors}, Metadata: {n_metadata}")
    
    # Read all metadata
    for i in range(n_metadata):
        key = read_str(f)
        vt = read_u32(f)
        skip_value(f, vt)
    
    metadata_end = f.tell()
    print(f"\nMetadata ends at: {metadata_end:,}")
    
    # Tensor info starts immediately
    tensor_info_start = metadata_end
    f.seek(tensor_info_start)
    
    tensors = []
    for i in range(min(20, n_tensors)):
        record_start = f.tell()
        n_dims = read_u64(f)
        dims = [read_u64(f) for _ in range(n_dims)]
        name_len = read_u32(f)
        name = f.read(name_len).decode('utf-8', errors='replace')
        ggml_type = read_u32(f)
        rel_offset = read_u64(f)
        record_end = f.tell()
        
        tensors.append({
            'idx': i,
            'start': record_start,
            'end': record_end,
            'name': name,
            'dims': dims,
            'type': ggml_type,
            'rel_off': rel_offset,
        })
        print(f"  [{i}] {name} @ {record_start:,} dims={dims} type={ggml_type} rel={rel_offset:,}")
    
    tensor_info_end = f.tell()
    
    # Align data offset
    alignment = 32
    data_offset = tensor_info_end
    if data_offset % alignment:
        data_offset += alignment - (data_offset % alignment)
    
    print(f"\nTensor info: {tensor_info_start:,} - {tensor_info_end:,}")
    print(f"Data offset: {data_offset:,}")
    
    # Show absolute offsets for first 20
    print(f"\n{'Idx':>4} {'Name':<40} {'AbsOffset':>12} {'NextAbs':>12}")
    for i, t in enumerate(tensors):
        abs_off = data_offset + t['rel_off']
        next_abs = data_offset + tensors[i+1]['rel_off'] if i+1 < len(tensors) else file_size
        print(f"{t['idx']:>4} {t['name']:<40} {abs_off:>12,} {next_abs:>12,}")
