#!/usr/bin/env python3
import sys

filepath = r'F:\rawrxd\src\deep2\K2GlobalTensorIndex.hpp'

# Read as raw bytes
with open(filepath, 'rb') as f:
    raw = f.read()

print(f'File size: {len(raw)} bytes')

# Check for UTF-16 LE BOM (ff fe)
if raw.startswith(b'\xff\xfe'):
    print('Has UTF-16 LE BOM, stripping it')
    # Decode as UTF-16 LE without BOM
    content = raw[2:].decode('utf-16-le')
    print('Successfully decoded as UTF-16 LE')
else:
    try:
        content = raw.decode('utf-16')
        print('Decoded as UTF-16')
    except:
        print('Could not decode file')
        sys.exit(1)

# Search for key patterns
for pattern in ['#pragma once', '#include <filesystem>', 'namespace Deep2', 'class K2GlobalTensorIndex']:
    if pattern in content:
        idx = content.index(pattern)
        line_num = content[:idx].count('\n') + 1
        print(f'Found "{pattern}" at line {line_num}')
    else:
        print(f'NOT found: {pattern}')

# Print first 500 chars (decoded)
print(f'\nFirst 500 chars: {content[:500]}')
