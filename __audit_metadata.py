#!/usr/bin/env python3
"""Audit GGUF metadata to establish ground truth for parser fixes."""
import struct
import sys

path = r'F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf'

def read_u32(f): return struct.unpack('<I', f.read(4))[0]
def read_u64(f): return struct.unpack('<Q', f.read(8))[0]
def read_str(f):
    n = read_u64(f)
    return f.read(n).decode('utf-8', errors='replace')

def read_val(f, vtype):
    if vtype == 0:   return f.read(1)[0]
    elif vtype == 1: return struct.unpack('<b', f.read(1))[0]
    elif vtype == 2: return struct.unpack('<H', f.read(2))[0]
    elif vtype == 3: return struct.unpack('<h', f.read(2))[0]
    elif vtype == 4: return struct.unpack('<I', f.read(4))[0]
    elif vtype == 5: return struct.unpack('<i', f.read(4))[0]
    elif vtype == 6: return struct.unpack('<f', f.read(4))[0]
    elif vtype == 7: return f.read(1)[0] != 0
    elif vtype == 8: return read_str(f)
    elif vtype == 9:
        arr_type = read_u32(f)
        arr_len = read_u64(f)
        elem_sizes = {0:1,1:1,2:2,3:2,4:4,5:4,6:4,7:1,8:0,9:0,10:8,11:8,12:8}
        if arr_type == 8:
            return [read_str(f) for _ in range(arr_len)]
        elif arr_type == 9:
            return []
        else:
            sz = elem_sizes.get(arr_type, 1)
            f.read(arr_len * sz)
            return []
    elif vtype == 10: return struct.unpack('<Q', f.read(8))[0]
    elif vtype == 11: return struct.unpack('<q', f.read(8))[0]
    elif vtype == 12: return struct.unpack('<d', f.read(8))[0]
    return None

with open(path, 'rb') as f:
    magic = f.read(4)
    version = read_u32(f)
    n_tensors = read_u64(f)
    n_metadata = read_u64(f)
    print(f'Magic: {magic}, Version: {version}, Tensors: {n_tensors}, Metadata: {n_metadata}')
    print()
    for i in range(n_metadata):
        key = read_str(f)
        vtype = read_u32(f)
        val = read_val(f, vtype)
        if isinstance(val, list):
            print(f'{key}: <array[{len(val)}]>')
        elif isinstance(val, str):
            print(f'{key}: "{val}"')
        elif val is not None:
            print(f'{key}: {val}')
