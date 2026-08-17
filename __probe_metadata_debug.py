#!/usr/bin/env python3
"""
Debug metadata parsing to find where cursor goes wrong.
"""
import struct

path = r'F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf'

def read_u32(f):
    return struct.unpack('<I', f.read(4))[0]

def read_u64(f):
    return struct.unpack('<Q', f.read(8))[0]

def read_str(f):
    n = read_u64(f)
    return f.read(n)

with open(path, 'rb') as f:
    magic = f.read(4)
    version = read_u32(f)
    n_tensors = read_u64(f)
    n_metadata = read_u64(f)

    print(f'Header: magic={magic}, version={version}, tensors={n_tensors}, metadata={n_metadata}')
    print()

    for i in range(n_metadata):
        pos = f.tell()
        key = read_str(f).decode('utf-8', errors='replace')
        vtype = read_u32(f)

        type_names = {
            0: 'UINT8', 1: 'INT8', 2: 'UINT16', 3: 'INT16',
            4: 'UINT32', 5: 'INT32', 6: 'FLOAT32', 7: 'BOOL',
            8: 'STRING', 9: 'ARRAY', 10: 'UINT64', 11: 'INT64', 12: 'FLOAT64'
        }
        tn = type_names.get(vtype, f'UNKNOWN({vtype})')

        # Print last 10 metadata entries
        if i >= n_metadata - 15:
            print(f'{i:3d} @ {pos:8d}: {key:<50s} type={tn}')

        # Skip value
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
        else:
            print(f'  UNKNOWN TYPE {vtype} at offset {f.tell()}')
            break

    end_pos = f.tell()
    print(f'\nMetadata end: {end_pos}')
    print(f'Next 32 bytes: {f.read(32).hex()}')
