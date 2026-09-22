import re, os, sys
content = open(r'f:\~dev\rawrxd\CMakeLists.txt', 'r', encoding='utf-8').read()
# Use regex to find set(SOURCES ... )
m = re.search(r'set\s*\(\s*SOURCES\s+(.*?)\n\)', content, re.DOTALL)
if not m:
    print('set(SOURCES not found via regex')
    sys.exit(1)
block = m.group(1)
lines = block.splitlines()
files = []
for line in lines:
    line = line.strip()
    if not line:
        continue
    if line.startswith('#'):
        continue
    line = line.rstrip(')')
    files.append(line)
print(f'Total SOURCES lines: {len(files)}')
missing = [f for f in files if not os.path.exists(f'f:\\~dev\\rawrxd\\{f}')]
print(f'Missing files: {len(missing)}')
for f in missing:
    print(f'  MISSING: {f}')
