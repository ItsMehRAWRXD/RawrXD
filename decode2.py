#!/usr/bin/env python3
import sys

filepath = r'F:\rawrxd\src\deep2\K2GlobalTensorIndex.hpp'

# Read the file as bytes
with open(filepath, 'rb') as f:
    data = f.read()

# Decode as UTF-8
c = data.decode('utf-8', errors='replace')

# Encode as latin-1 to avoid encoding issues when writing
c_latin1 = c.encode('latin-1', errors='replace')

# Write first 500 chars to file in binary mode
with open(r'F:\rawrxd\decode_output.txt', 'wb') as f:
    f.write(b'Decoded length: ' + str(len(c)).encode() + b'\n')
    f.write(c_latin1[:500])
    f.write(b'\n\n')

# Search for key patterns and write to file
for pattern, label in [('pragma', 'pragma'), ('filesystem', 'filesystem'), ('optional', 'optional'), ('Deep2', 'Deep2')]:
    idx = c.find(pattern)
    with open(r'F:\rawrxd\decode_output.txt', 'ab') as f:
        if idx >= 0:
            context_start = max(0, idx - 30)
            context_end = min(len(c), idx + 30)
            f.write(f'Found "{label}" at index {idx}, context: '.encode())
            ctx = c_latin1[context_start:context_end]
            f.write(ctx)
            f.write(b'\n')
        else:
            f.write(f'NOT found: {label}\n'.encode())