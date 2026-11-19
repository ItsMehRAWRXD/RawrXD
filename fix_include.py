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

# Find the exact lines and content
lines = content.split('\n')

# Find line numbers
pragma_once_line = content[:pragma_once_idx].count('\n') + 1
include_fs_line = content[:include_fs_idx].count('\n') + 1
namespace_d2_line = content[:namespace_d2_idx].count('\n') + 1

print(f'#pragma once on line: {pragma_once_line}')
print(f'#include <filesystem> on line: {include_fs_line}')
print(f'namespace Deep2 on line: {namespace_d2_line}')

# Show the relevant lines
print()
print('Lines around #pragma once:')
for i in range(max(0, pragma_once_line-3), min(len(lines), pragma_once_line+3)):
    print(f'  Line {i+1}: {lines[i]}')

print()
print('Lines around #include <filesystem>:')
for i in range(max(0, include_fs_line-3), min(len(lines), include_fs_line+3)):
    print(f'  Line {i+1}: {lines[i]}')

print()
print('Lines around namespace Deep2:')
for i in range(max(0, namespace_d2_line-3), min(len(lines), namespace_d2_line+3)):
    print(f'  Line {i+1}: {lines[i]}')

# Now do the fix: move #include <filesystem> to right after #pragma once
# Step 1: Remove #include <filesystem> from its current position
# Step 2: Insert it right after #pragma once

# The new content: #pragma once\n#include <filesystem>\n[rest of original content starting from line after #pragma once]
# But we need to be careful - remove the old #include <filesystem> line and insert new one

# Let's build the new content
# Find what comes after #pragma once on the next line
pragma_once_line_idx = None
for i, line in enumerate(lines):
    if line.strip().startswith('#pragma once'):
        pragma_once_line_idx = i
        break

# Get the line after #pragma once
after_pragma = lines[pragma_once_line_idx + 1] if pragma_once_line_idx + 1 < len(lines) else ''

# Check if there's already an #include on the next line
if after_pragma.strip().startswith('#include'):
    # The next line is an include - we'll replace it with filesystem, and move the old one
    pass

# Actually, let's just do a surgical approach:
# 1. Find the #include <filesystem> line and remove it
# 2. Insert #include <filesystem> right after #pragma once

# Remove the old #include <filesystem> line
new_lines = []
for i, line in enumerate(lines):
    if '#include <filesystem>' in line:
        continue  # skip this line
    new_lines.append(line)

# Now insert #include <filesystem> right after #pragma once
# Find where #pragma once is
for i, line in enumerate(new_lines):
    if line.strip().startswith('#pragma once'):
        # Insert after this line
        new_lines.insert(i + 1, '#include <filesystem>')
        break

# Write the new content
new_content = '\n'.join(new_lines) + '\n'

with open(r'F:\rawrxd\src\deep2\K2GlobalTensorIndex.hpp', 'w', encoding='utf-16') as f:
    f.write('\ufeff' + new_content.encode('utf-16')[2:])  # Add BOM

print()
print('Fix applied! Re-analyzing...')

# Verify
content2 = new_content
new_include_fs_idx = content2.find('#include <filesystem>')
new_namespace_d2_idx = content2.find('namespace Deep2')
print(f'New #include <filesystem> at idx: {new_include_fs_idx}')
print(f'New namespace Deep2 at idx: {new_namespace_d2_idx}')
print(f'Include is before namespace: {new_include_fs_idx < new_namespace_d2_idx}')