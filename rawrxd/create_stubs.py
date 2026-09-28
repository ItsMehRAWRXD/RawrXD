import re, os

with open('CMakeLists.txt','r') as f:
    content = f.read()

# Find all source-like files referenced in CMakeLists.txt
files = set(re.findall(r'src/[^\s\)\"]+\.(?:cpp|c|asm|h|hpp|rc)', content))
files.update(re.findall(r'tests/[^\s\)\"]+\.(?:cpp|c|asm|h|hpp|rc)', content))
files.update(re.findall(r'certs/[^\s\)\"]+\.(?:cpp|c|asm|h|hpp|rc)', content))
files.update(re.findall(r'B014/[^\s\)\"]+\.(?:cpp|c|asm|h|hpp|rc)', content))
files.update(re.findall(r'rguf_source/[^\s\)\"]+\.(?:cpp|c|asm|h|hpp|rc)', content))
files.update(re.findall(r'pe_tools/[^\s\)\"]+\.(?:cpp|c|asm|h|hpp|rc)', content))

missing = [f for f in sorted(files) if not os.path.exists(f) and not '*' in f and not '..' in f]
print(f'Total unique missing files: {len(missing)}')

for fn in missing:
    os.makedirs(os.path.dirname(fn), exist_ok=True)
    ext = os.path.splitext(fn)[1].lower()
    if ext in ['.cpp', '.c', '.cc']:
        content = '// Auto-generated stub\n'
    elif ext in ['.h', '.hpp']:
        content = '#pragma once\n// Auto-generated stub\n'
    elif ext == '.asm':
        content = '; Auto-generated stub\nEND\n'
    elif ext == '.rc':
        content = '// Auto-generated stub\n'
    else:
        content = '// Auto-generated stub\n'
    with open(fn, 'w') as f:
        f.write(content)
    print(f'Created stub: {fn}')

print(f'Done. Created {len(missing)} stub files.')
