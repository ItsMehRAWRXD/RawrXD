import os, re, sys

CMAKE_PATH = r'f:\~dev\rawrxd\CMakeLists.txt'
SOURCE_RE = re.compile(r'^(?:\s*(?:[A-Za-z0-9_]+_)?SOURCES\s*\()?\s*([a-zA-Z_][a-zA-Z0-9_/\.\-]+\.(?:cpp|c|asm|s|cc|cxx))\s*\)?')

with open(CMAKE_PATH, 'r', encoding='utf-8') as f:
    lines = f.readlines()

missing = []
for i, line in enumerate(lines, 1):
    line = line.split('#')[0]  # strip comments
    m = SOURCE_RE.match(line)
    if m:
        filepath = m.group(1).strip()
        full = os.path.join(r'f:\~dev\rawrxd', filepath)
        if not os.path.isfile(full):
            missing.append((i, filepath))

print(f"Total missing: {len(missing)}")
for line_no, filepath in missing[:200]:
    print(f"  Line {line_no}: {filepath}")
if len(missing) > 200:
    print(f"  ... and {len(missing)-200} more")
