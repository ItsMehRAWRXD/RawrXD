#!/usr/bin/env python3
# Fix include order in K2GlobalTensorIndex.hpp
# Move #include <filesystem> to be right after #pragma once

filepath = r'F:\rawrxd\src\deep2\K2GlobalTensorIndex.hpp'

with open(filepath, 'rb') as f:
    raw = f.read()
# Try UTF-8 first, then fall back to other encodings
try:
    content = raw.decode('utf-8-sig')  # handles BOM
except UnicodeDecodeError:
    content = raw.decode('latin-1')

# Replace the include section
# Old: #include <filesystem> is after #include <optional>
# New: #include <filesystem> is right after #pragma once

# Find the pattern and replace
old_pattern = '#pragma once\n#include "KimiK2Config.hpp"\n#include "TensorView.hpp"\n#include <cstdint>\n#include <string>\n#include <vector>\n#include <unordered_map>\n#include <optional>\n#include <filesystem>\n\nnamespace Deep2 {'

new_pattern = '#pragma once\n#include <filesystem>\n#include "KimiK2Config.hpp"\n#include "TensorView.hpp"\n#include <cstdint>\n#include <string>\n#include <vector>\n#include <unordered_map>\n#include <optional>\n\nnamespace Deep2 {'

if old_pattern in content:
    content = content.replace(old_pattern, new_pattern, 1)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    print('Successfully moved #include <filesystem> to after #pragma once')
else:
    print('Pattern not found, trying alternative match')
    # Try simpler pattern
    if '#include <filesystem>' in content:
        # Find line number
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if '#include <filesystem>' in line:
                print(f'Found #include <filesystem> at line {i+1}')
                # Print surrounding lines
                for j in range(max(0,i-2), min(len(lines), i+3)):
                    print(f'  Line {j+1}: {lines[j][:80]}')
                break
    else:
        print('#include <filesystem> not found in file')

# Write the modified content
with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)
print('Done writing file')
