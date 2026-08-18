#!/usr/bin/env python3
import struct

path = r'F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf'

def read_u32(f): return struct.unpack('<I', f.read(4))[0]
def read_u64(f): return struct.unpack('<Q', f.read(8))[0]
def read_str(f):
    n = read_u64(f)
    return f.read(n).decode('utf-8', errors='replace')

with open(path, 'rb') as f:
    magic = f.read(4)
    version = read_u32(f)
    n_tensors = read_u64(f)
    n_metadata = read_u64(f)
    print(f'Version: {version}, Tensors: {n_tensors}, Metadata: {n_metadata}')
    for i in range(n_metadata):
        key = read_str(f)
        vtype = read_u32(f)
        if vtype == 0:   val = struct.unpack('<B', f.read(1))[0]
        elif vtype == 1: val = struct.unpack('<b', f.read(1))[0]
        elif vtype == 2: val = struct.unpack('<H', f.read(2))[0]
        elif vtype == 3: val = struct.unpack('<h', f.read(2))[0]
        elif vtype == 4: val = struct.unpack('<I', f.read(4))[0]
        elif vtype == 5: val = struct.unpack('<i', f.read(4))[0]
        elif vtype == 6: val = struct.unpack('<f', f.read(4))[0]
        elif vtype == 7: val = struct.unpack('<B', f.read(1))[0] != 0
        elif vtype == 8: val = read_str(f)
        elif vtype == 9:
            etype = read_u32(f)
            ecnt = read_u64(f)
            val = f'[array:{ecnt}]'
            for _ in range(ecnt):
                if etype == 0: f.read(1)
                elif etype == 1: f.read(1)
                elif etype == 2: f.read(2)
                elif etype == 3: f.read(2)
                elif etype == 4: f.read(4)
                elif etype == 5: f.read(4)
                elif etype == 6: f.read(4)
                elif etype == 7: f.read(1)
                elif etype == 8: read_str(f)
                elif etype == 10: f.read(8)
                elif etype == 11: f.read(8)
                elif etype == 12: f.read(8)
        elif vtype == 10: val = struct.unpack('<Q', f.read(8))[0]
        elif vtype == 11: val = struct.unpack('<q', f.read(8))[0]
        elif vtype == 12: val = struct.unpack('<d', f.read(8))[0]
        else: val = f'UNKNOWN_TYPE_{vtype}'
        print(f'{key} = {val}')
