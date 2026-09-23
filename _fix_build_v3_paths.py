import re
path = r'F:\~dev\rawrxd\src\deep2\Deep2Engine.cpp'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

old = r'F:\\~dev\\rawrxd\\win32ide_strict\\build_v3\\Release\\gen_debug.txt'
new = r'F:\\~dev\\rawrxd\\win32ide_strict\\build_v4\\Release\\gen_debug.txt'

count = content.count(old)
if count > 0:
    content = content.replace(old, new)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Replaced {count} occurrences")
else:
    print("No occurrences found")
