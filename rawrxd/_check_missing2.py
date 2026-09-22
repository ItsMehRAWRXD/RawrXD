import re, os, sys
content = open('CMakeLists.txt', 'r', encoding='utf-8').read()
# Find set(SOURCES block, capture until the matching ) at start of line
start = content.find('set(SOURCES')
if start == -1:
    print('set(SOURCES not found')
    sys.exit(1)
paren_depth = 0
end = start
for i in range(start, len(content)):
    ch = content[i]
    if ch == '(':
        paren_depth += 1
    elif ch == ')':
        paren_depth -= 1
        if paren_depth == 0:
            end = i
            break
block = content[start:end+1]
lines = block.splitlines()[1:]
files = []
for line in lines:
    line = line.strip()
    if line.startswith('#'):
        continue
    if not line:
        continue
    # remove trailing ) if present
    line = line.rstrip(')')
    files.append(line)
print(f'Total SOURCES lines: {len(files)}')
missing = [f for f in files if not os.path.exists(f)]
print(f'Missing files: {len(missing)}')
for f in missing:
    print(f'  MISSING: {f}')
