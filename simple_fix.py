# Simple script to fix include order in K2GlobalTensorIndex.hpp
# Moves #include <filesystem> to right after #pragma once

import os

filepath = r'F:\rawrxd\src\deep2\K2GlobalTensorIndex.hpp'

# Read the file as bytes
with open(filepath, 'rb') as f:
    data = f.read()

# Find positions of key strings
# Search for #pragma once, #include <filesystem>, #include <optional>, namespace Deep2
# These are in UTF-16 LE with possible BOM

# Find #pragma once
pragma_once = b'#pragma once'
fs_include = b'#include <filesystem>'
opt_include = b'#include <optional>'
ns_deep2 = b'namespace Deep2'

# Find positions
pragma_pos = data.find(pragma_once)
fs_pos = data.find(fs_include)
opt_pos = data.find(opt_include)
ns_pos = data.find(ns_deep2)

print(f'pragma_once at byte {pragma_pos}')
print(f'filesystem at byte {fs_pos}')
print(f'optional at byte {opt_pos}')
print(f'namespace Deep2 at byte {ns_pos}')

# We need to move #include <filesystem> to right after #pragma once
# Current order (from earlier analysis): pragma at 498, filesystem at 681, optional at some position, namespace at 708

# Strategy: 
# 1. Remove #include <filesystem> from its current position
# 2. Insert it right after #pragma once

# Let's work with the decoded content
# First, let me try decoding with different methods

# Check for BOM
if data[:3] == b'\xef\xbb\xbf':
    print('UTF-8 BOM detected, skipping')
    data = data[3:]
    content = data.decode('utf-16-le')
else:
    content = data.decode('utf-16-le')

# Now find the positions again in the decoded content
pragma_pos2 = content.find('#pragma once')
fs_pos2 = content.find('#include <filesystem>')
opt_pos2 = content.find('#include <optional>')
ns_pos2 = content.find('namespace Deep2')

print(f'\nDecoded pragma_once at: {pragma_pos2}')
print(f'Decoded filesystem at: {fs_pos2}')
print(f'Decoded optional at: {opt_pos2}')
print(f'Decoded namespace Deep2 at: {ns_pos2}')

# Show the includes section
# Find where the standard includes are
includes_section = content[pragma_pos2:ns_pos2]
print(f'\nIncludes section ({len(includes_section)} chars):')
print(includes_section)