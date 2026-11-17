#!/usr/bin/env python3
# Restore and fix K2GlobalTensorIndex.hpp
# 1. Read the file with proper BOM handling
# 2. Move #include <filesystem> to after #pragma once
# 3. Write back with proper encoding

import sys

filepath = r'F:\rawrxd\src\deep2\K2GlobalTensorIndex.hpp'

# Read the file with proper encoding handling
with open(filepath, 'rb') as f:
    raw = f.read()

# Decode with BOM awareness
if raw.startswith(b'\xef\xbb\xbf'):
    content = raw[3:].decode('utf-8')
else:
    try:
        content = raw.decode('utf-8')
    except UnicodeDecodeError:
        content = raw.decode('utf-8-sig')  # handles BOM automatically

# Check if #include <filesystem> is in the file
if '#include <filesystem>' not in content:
    print('ERROR: #include <filesystem> not found in file')
    sys.exit(1)

# Replace the include section
# Old pattern: #pragma once followed by includes, with <filesystem> after <optional>
old_pattern = """#pragma once
#include "KimiK2Config.hpp"
#include "TensorView.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <filesystem>

namespace Deep2 {"""

new_pattern = """#pragma once
#include <filesystem>
#include "KimiK2Config.hpp"
#include "TensorView.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>

namespace Deep2 {"""

if old_pattern in content:
    content = content.replace(old_pattern, new_pattern, 1)
    print('Successfully moved #include <filesystem> to after #pragma once')
else:
    print('Old pattern not found, searching for alternative')
    # Try to find where <filesystem> currently is
    if '#include <filesystem>' in content:
        idx = content.index('#include <filesystem>')
        # Print context
        start = max(0, idx - 50)
        end = min(len(content), idx + 100)
        print(f'Found at index {idx}')
        print(f'Context: {repr(content[start:end])[:500]}')
    sys.exit(1)

# Write the modified content back
with open(filepath, 'wb') as f:
    # Write UTF-8 with BOM to match original format
    f.write(b'\xef\xbb\xbf' + content.encode('utf-8'))

print('File written successfully with BOM')

# Verify the change
with open(filepath, 'r', encoding='utf-8-sig') as f:
    verify = f.read()
if new_pattern in verify:
    print('Verification successful: new pattern found in file')
else:
    print('WARNING: Verification failed - new pattern not found')
