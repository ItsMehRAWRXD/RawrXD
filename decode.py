#!/usr/bin/env python3
import sys

filepath = r'F:\rawrxd\src\deep2\K2GlobalTensorIndex.hpp'

# Read the file as bytes
with open(filepath, 'rb') as f:
    data = f.read()

print(f'File size: {len(data)} bytes')
print(f'First 10 bytes hex: {data[:10].hex()}')

# Try different decodings
for enc in ['utf-16', 'utf-16-le', 'utf-16-be', 'utf-8', 'utf-8-sig']:
    try:
        c = data.decode(enc)
        print(f'Successfully decoded as {enc}')
        # Check for key strings
        for s in ['#pragma once', '#include <filesystem>', '#include <optional>', 'namespace Deep2']:
            if s in c:
                idx = c.index(s)
                line_num = c[:idx].count('\n') + 1
                print(f'  Found "{s}" at line {line_num}')
            else:
                print(f'  NOT found: {s}')
        # Print first 300 chars
        print(f'  First 300 chars: {c[:300]}')
        break
    except Exception as e:
        print(f'Failed as {enc}: {e}')