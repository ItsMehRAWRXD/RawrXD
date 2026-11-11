#!/usr/bin/env python3
import struct
from pathlib import Path

corrupt = Path("G:/~dev/rawrxd/models/DeepSeek-V2-Lite-Chat.Q4_K_M.gguf")
C = 293993216

with open(corrupt, 'rb') as f:
    f.seek(C)
    data = f.read(8192)
    floats = struct.unpack('<2048f', data)
    
    nonfinite = 0
    nan_count = 0
    first_nonfinite = -1
    for i, v in enumerate(floats):
        if not (float('-inf') < v < float('inf')):
            nonfinite += 1
            if v != v:
                nan_count += 1
            if first_nonfinite == -1:
                first_nonfinite = i
    
    print(f'Original corrupted GGUF at C={C}:')
    print(f'  NONFINITE={nonfinite}')
    print(f'  NAN={nan_count}')
    print(f'  FIRST_NONFINITE={first_nonfinite}')
    print(f'  First 5 floats: {[f"{v:.6e}" for v in floats[:5]]}')
