import re, os
content = open('CMakeLists.txt', 'r', encoding='utf-8').read()
m = re.search(r'set\(SOURCES\s+(.*?)(?:\n\S|\n\))', content, re.DOTALL)
if not m:
    print('no match')
else:
    raw = m.group(1)
    files = [x.strip().strip('\"') for x in raw.split('\n') if x.strip() and not x.strip().startswith('#')]
    missing = [f for f in files if not os.path.exists(f)]
    print(f'Total SOURCES lines: {len(files)}')
    print(f'Missing files: {len(missing)}')
    for f in missing:
        print(f'  MISSING: {f}')
