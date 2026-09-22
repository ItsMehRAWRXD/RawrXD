import os

# Read CMakeLists.txt
with open('CMakeLists.txt', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Extract SOURCES list
in_sources = False
paren_depth = 0
sources = []
for i, line in enumerate(lines):
    stripped = line.strip()
    if stripped.startswith('set(SOURCES'):
        in_sources = True
        paren_depth = stripped.count('(') - stripped.count(')')
        continue
    if not in_sources:
        continue
    paren_depth += stripped.count('(') - stripped.count(')')
    if paren_depth <= 0 and stripped.startswith(')'):
        break
    if stripped and not stripped.startswith('#'):
        path = stripped.strip('"').strip()
        if path:
            sources.append(path)

print(f'Total SOURCES entries: {len(sources)}')
missing = []
for s in sources:
    if not os.path.exists(s):
        missing.append(s)
print(f'Missing: {len(missing)}')

# Group by directory
from collections import Counter
dirs = Counter()
for m in missing:
    d = os.path.dirname(m) if '/' in m else 'root'
    dirs[d] += 1

print('\nMissing by directory:')
for d, c in dirs.most_common(30):
    print(f'  {d}: {c}')

print('\nFirst 50 missing files:')
for m in missing[:50]:
    print(f'  {m}')

# Check which actual files exist that could replace them
print('\n\nChecking actual src/ structure...')
actual_files = []
for root, _, files in os.walk('src'):
    for f in files:
        if f.endswith('.cpp'):
            actual_files.append(os.path.join(root, f).replace('\\', '/'))
print(f'Actual .cpp files in src/: {len(actual_files)}')

# Check for potential replacements
print('\nPotential replacements for missing files:')
for m in missing[:30]:
    basename = os.path.basename(m).replace('.cpp', '')
    candidates = [a for a in actual_files if basename.lower() in a.lower()]
    if candidates:
        print(f'  {m} -> {candidates[0]}')
    else:
        print(f'  {m} -> NO CANDIDATE')
