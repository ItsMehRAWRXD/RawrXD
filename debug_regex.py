import re

with open('F:/~dev/rawrxd/CMakeLists.txt', 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

# Find all set(ASM_*_SRC) declarations referencing .asm
src_pattern = re.compile(r'^\s*set\(ASM_([A-Z0-9_]+)_SRC\s+"(.+?\.asm)"\)', re.MULTILINE)

matches = list(src_pattern.finditer(content))
print(f'Found {len(matches)} ASM_SRC declarations')

for m in matches[:5]:
    print(f'  Var: {m.group(1)}, Path: {m.group(2)}')
