#!/usr/bin/env python3
"""
K2-001: Corrected GGUF tensor-info parser
Parses tensor table sequentially from aligned start.
"""
import struct
import sys

path = r'F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf'

def read_u32(f):
    return struct.unpack('<I', f.read(4))[0]

def read_u64(f):
    return struct.unpack('<Q', f.read(8))[0]

def read_str(f):
    n = read_u64(f)
    return f.read(n)

def align_offset(off, alignment=32):
    return (off + alignment - 1) & ~(alignment - 1)

with open(path, 'rb') as f:
    # Header
    magic = f.read(4)
    version = read_u32(f)
    n_tensors = read_u64(f)
    n_metadata = read_u64(f)

    print(f'Magic:   {magic}')
    print(f'Version: {version}')
    print(f'Tensors: {n_tensors}')
    print(f'Metadata: {n_metadata}')

    # Skip metadata section
    for i in range(n_metadata):
        key = read_str(f).decode('utf-8', errors='replace')
        vtype = read_u32(f)

        if vtype == 0:   f.read(1)
        elif vtype == 1: f.read(1)
        elif vtype == 2: f.read(2)
        elif vtype == 3: f.read(2)
        elif vtype == 4: f.read(4)
        elif vtype == 5: f.read(4)
        elif vtype == 6: f.read(4)
        elif vtype == 7: f.read(1)
        elif vtype == 8: read_str(f)
        elif vtype == 9:
            arr_type = read_u32(f)
            arr_len = read_u64(f)
            elem_size = {0:1, 1:1, 2:2, 3:2, 4:4, 5:4, 6:4, 7:1, 10:8, 11:8, 12:8}.get(arr_type, 1)
            if arr_type == 8:
                for _ in range(arr_len): read_str(f)
            else:
                f.read(arr_len * elem_size)
        elif vtype == 10: f.read(8)
        elif vtype == 11: f.read(8)
        elif vtype == 12: f.read(8)

    metadata_end = f.tell()
    tensor_info_start = align_offset(metadata_end, 32)

    print(f'Metadata end:      {metadata_end}')
    print(f'Tensor info start: {tensor_info_start}')

    # Seek to aligned tensor info start
    f.seek(tensor_info_start)

    # Parse first 20 tensor records
    tensors = []
    for i in range(min(20, n_tensors)):
        record_start = f.tell()
        name_len = read_u64(f)
        name = f.read(name_len).decode('utf-8', errors='replace')
        n_dims = read_u32(f)
        dims = [read_u64(f) for _ in range(n_dims)]
        ggml_type = read_u32(f)
        offset = read_u64(f)

        tensors.append({
            'index': i,
            'record_start': record_start,
            'name': name,
            'dims': dims,
            'ggml_type': ggml_type,
            'offset': offset,
        })

    tensor_info_end = f.tell()
    data_offset = align_offset(tensor_info_end, 32)

    print(f'Tensor info end:   {tensor_info_end}')
    print(f'Data offset:       {data_offset}')
    print()
    print(f"{'Idx':<4} {'Name':<40} {'Dims':<25} {'Type':<6} {'RelOff':<12} {'AbsOff':<12}")
    print('-' * 105)

    for t in tensors:
        abs_off = data_offset + t['offset']
        dims_str = 'x'.join(str(d) for d in t['dims'])
        print(f"{t['index']:<4} {t['name']:<40} {dims_str:<25} {t['ggml_type']:<6} {t['offset']:<12} {abs_off:<12}")
