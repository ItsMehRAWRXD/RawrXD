import re
import os

with open(r'F:\rawrxd\src\Deep2Engine.h', 'r', encoding='utf-16-le', errors='ignore') as f:
    content = f.read()

includes = re.findall(r'#include\s+[<"]([^">]+)[>"]', content)
missing = []
found = []
for inc in sorted(set(includes)):
    paths = [
        f'F:\\rawrxd\\src\\{inc}',
        f'F:\\rawrxd\\src\\deep2\\{inc}',
    ]
    found_path = None
    for p in paths:
        if os.path.exists(p):
            found_path = p
            break
    if found_path:
        found.append(inc)
    else:
        missing.append(inc)

print('FOUND:')
for f in found:
    print(f'  {f}')
print()
print('MISSING:')
for m in missing:
    print(f'  {m}')
