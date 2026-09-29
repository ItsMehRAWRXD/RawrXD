import re
c = open(r'F:\~dev\rawrxd\src\core\gold_command_providers.cpp', encoding='utf-8', errors='replace').read()
# Find ALL void X() {} patterns anywhere in the file
syms = re.findall(r'void\s+(\w+)\s*\(\s*\)\s*\{[^}]*\}', c)
print('count:', len(syms))
for s in sorted(set(syms)):
    print(' ', s)
