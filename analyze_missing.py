import re, os

cmake_path = r'f:\~dev\rawrxd\CMakeLists.txt'
with open(cmake_path, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

# Find all if(BUILD_*) blocks and check for missing sources
build_if_pattern = re.compile(r'^if\((BUILD_\w+)[^)]*\)', re.MULTILINE)
matches = list(build_if_pattern.finditer(content))
print(f'Found {len(matches)} if(BUILD_*) blocks')

options_to_disable = set()
for i, match in enumerate(matches):
    opt_name = match.group(1)
    start = match.end()
    # Find matching endif()
    depth = 1
    j = start
    while j < len(content) and depth > 0:
        next_if = content.find('if(', j)
        next_endif = content.find('endif()', j)
        if next_if != -1 and next_if < next_endif:
            line_start = content.rfind('\n', 0, next_if) + 1
            if not content[line_start:next_if].strip().startswith('#'):
                depth += 1
            j = next_if + 3
        elif next_endif != -1:
            depth -= 1
            j = next_endif + 7
        else:
            break
    block = content[start:j]
    src_refs = re.findall(r'(?:src|tests|certs)/[\w./]+', block)
    missing = []
    for sr in src_refs:
        full = os.path.join(r'f:\~dev\rawrxd', sr.replace('/', os.sep))
        if not os.path.exists(full):
            missing.append(sr)
    if missing:
        options_to_disable.add(opt_name)

print(f'Options to disable: {len(options_to_disable)}')
for opt in sorted(options_to_disable):
    print(f'  {opt}')

# Also collect missing files for core targets (not inside BUILD_ blocks)
core_missing = []
# RawrEngine
m = re.search(r'add_executable\(RawrEngine[^)]+\)', content)
if m:
    srcs = re.findall(r'src/[\w./]+', m.group(0))
    for sr in srcs:
        if not os.path.exists(os.path.join(r'f:\~dev\rawrxd', sr.replace('/', os.sep))):
            core_missing.append(('RawrEngine', sr))

print(f'\nCore targets with missing files: {len(core_missing)}')
for t, s in core_missing:
    print(f'  {t}: {s}')
