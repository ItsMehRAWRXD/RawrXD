with open(r'F:\rawrxd\src\deep2\K2GlobalTensorIndex.hpp', 'rb') as f:
    data = f.read()

# Strip UTF-8 BOM if present, then decode as utf-16
if data[:3] == b'\xef\xbb\xbf':
    data = data[3:]
content = data.decode('utf-16')

# Find key positions
pragma_once_idx = content.find('#pragma once')
include_fs_idx = content.find('#include <filesystem>')
namespace_d2_idx = content.find('namespace Deep2')

print(f'#pragma once at idx: {pragma_once_idx}')
print(f'#include <filesystem> at idx: {include_fs_idx}')
print(f'namespace Deep2 at idx: {namespace_d2_idx}')

# Split into lines
lines = content.split('\n')

# Find the line numbers
pragma_once_line = None
include_fs_line = None
for i, line in enumerate(lines):
    if line.strip().startswith('#pragma once'):
        pragma_once_line = i
    if '#include <filesystem>' in line:
        include_fs_line = i

print(f'#pragma once on line index: {pragma_once_line}')
print(f'#include <filesystem> on line index: {include_fs_line}')

# Step 1: Remove the #include <filesystem> line
new_lines = []
for i, line in enumerate(lines):
    if '#include <filesystem>' in line:
        continue  # skip this line
    new_lines.append(line)

# Step 2: Insert #include <filesystem> right after #pragma once
# Find the #pragma once line and insert after it
for i, line in enumerate(new_lines):
    if line.strip().startswith('#pragma once'):
        # Insert the #include <filesystem> on the next line
        new_lines.insert(i + 1, '#include <filesystem>')
        break

# Write the new content
new_content = '\n'.join(new_lines) + '\n'

# Encode as UTF-16 with BOM
encoded = new_content.encode('utf-16')
# The encoding adds an extra BOM, so replace or just write without extra
with open(r'F:\rawrxd\src\deep2\K2GlobalTensorIndex.hpp', 'wb') as f:
    f.write('\ufeff'.encode('utf-16') + encoded[2:])  # Add BOM, skip duplicate

print()
print('Fix applied! Verifying...')

# Verify the new positions
new_content2 = new_content
new_pragma_idx = new_content2.find('#pragma once')
new_fs_idx = new_content2.find('#include <filesystem>')
new_ns_idx = new_content2.find('namespace Deep2')
print(f'New #pragma once at idx: {new_pragma_idx}')
print(f'New #include <filesystem> at idx: {new_fs_idx}')
print(f'New namespace Deep2 at idx: {new_ns_idx}')
print(f'Include is before namespace: {new_fs_idx < new_ns_idx}')
print(f'Include is right after pragma: {new_fs_idx > new_pragma_idx and new_fs_idx < new_pragma_idx + 100}')