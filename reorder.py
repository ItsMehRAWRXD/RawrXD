#!/usr/bin/env python3
import sys

filepath = r'F:\rawrxd\src\deep2\K2GlobalTensorIndex.hpp'

# Read as binary
with open(filepath, 'rb') as f:
    raw = f.read()

# The file starts with UTF-8 BOM (0xEF 0xBB 0xBF) followed by UTF-16 LE content
# Skip the BOM if present
if raw[:3] == b'\xef\xbb\xbf':
    raw = raw[3:]

# Decode as UTF-16 LE
content = raw.decode('utf-16-le')

# Find key positions
pragma_idx = content.find('#pragma once')
fs_idx = content.find('#include <filesystem>')
opt_idx = content.find('#include <optional>')
ns_idx = content.find('namespace Deep2')

print(f'#pragma once at: {pragma_idx}')
print(f'#include <filesystem> at: {fs_idx}')
print(f'#include <optional> at: {opt_idx}')
print(f'namespace Deep2 at: {ns_idx}')

# Show character context around key positions
print()
print('Around #pragma once:')
start = max(0, pragma_idx - 50)
end = min(len(content), pragma_idx + 100)
print(content[start:end])

print()
print('Around #include <filesystem>:')
start = max(0, fs_idx - 50)
end = min(len(content), fs_idx + 100)
print(content[start:end])

print()
print('Around #include <optional>:')
start = max(0, opt_idx - 50)
end = min(len(content), opt_idx + 100)
print(content[start:end])

print()
print('Around namespace Deep2:')
start = max(0, ns_idx - 50)
end = min(len(content), ns_idx + 100)
print(content[start:end])