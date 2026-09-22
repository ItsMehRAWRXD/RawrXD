import re, os

def log(msg):
    print(msg)
    with open(r'f:\~dev\fix_cmake_log.txt', 'a', encoding='utf-8') as f:
        f.write(msg + '\n')

cmake_path = r'f:\~dev\rawrxd\CMakeLists.txt'
with open(cmake_path, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

# Reset log
with open(r'f:\~dev\fix_cmake_log.txt', 'w', encoding='utf-8') as f:
    f.write('')

log(f'CMakeLists.txt size: {len(content)} bytes')

# Find all if(BUILD_*) blocks and detect missing sources within them
build_if_pattern = re.compile(r'^if\((BUILD_\w+)[^)]*\)', re.MULTILINE)
matches = list(build_if_pattern.finditer(content))
log(f'Found {len(matches)} if(BUILD_*) blocks')

options_to_disable = set()
for match in matches:
    opt_name = match.group(1)
    start = match.end()
    # Find matching endif()
    depth = 1
    j = start
    while j < len(content) and depth > 0:
        next_if = content.find('if(', j)
        next_endif = content.find('endif()', j)
        if next_if != -1 and next_endif != -1:
            if next_if < next_endif:
                line_start = content.rfind('\n', 0, next_if) + 1
                if not content[line_start:next_if].strip().startswith('#'):
                    depth += 1
                j = next_if + 3
            else:
                depth -= 1
                j = next_endif + 7
        elif next_endif != -1:
            depth -= 1
            j = next_endif + 7
        else:
            break
    block = content[start:j]
    # Find any src/tests/certs path references
    src_refs = set(re.findall(r'(?:src|tests|certs)/[\w./-]+', block))
    missing = []
    for sr in src_refs:
        full = os.path.join(r'f:\~dev\rawrxd', sr.replace('/', os.sep))
        if not os.path.exists(full):
            missing.append(sr)
    if missing:
        options_to_disable.add(opt_name)
        log(f'  {opt_name}: {len(missing)} missing files')

log(f'\nTotal options to disable: {len(options_to_disable)}')
for opt in sorted(options_to_disable):
    log(f'  {opt}')

# Modify options
mod_count = 0
for opt_name in sorted(options_to_disable):
    old_pat = rf'^option\({re.escape(opt_name)}\s+"([^"]*)"\s+ON\)'
    if re.search(old_pat, content, re.MULTILINE):
        content = re.sub(old_pat, f'option({opt_name} "\\1" OFF)', content, flags=re.MULTILINE)
        mod_count += 1
        log(f'  Modified {opt_name} -> OFF')
    else:
        log(f'  Could not find option line for {opt_name}')

log(f'\nModified {mod_count} option lines')

# Now handle core targets not in BUILD_ blocks
# 1. RawrEngine - filter RAWR_ENGINE_SOURCES and RAWR_ENGINE_ASM_SOURCES
rawrengine_add = re.search(r'add_executable\(RawrEngine\s+([^)]+)\)', content)
if rawrengine_add:
    srcs = re.findall(r'src/[\w./-]+', rawrengine_add.group(1))
    missing_srcs = [s for s in srcs if not os.path.exists(os.path.join(r'f:\~dev\rawrxd', s.replace('/', os.sep)))]
    log(f'\nRawrEngine missing in source list: {missing_srcs}')

# 2. RawrXD_Gold
rawrgold_add = re.search(r'add_executable\(RawrXD_Gold\s+([^)]+)\)', content)
if rawrgold_add:
    srcs = re.findall(r'src/[\w./-]+', rawrgold_add.group(1))
    missing_srcs = [s for s in srcs if not os.path.exists(os.path.join(r'f:\~dev\rawrxd', s.replace('/', os.sep)))]
    log(f'RawrXD_Gold missing in source list: {missing_srcs}')

# 3. RawrXD-Win32IDE
win32ide_add = re.search(r'add_executable\(RawrXD-Win32IDE\s+([^)]+)\)', content)
if win32ide_add:
    srcs = re.findall(r'src/[\w./-]+', win32ide_add.group(1))
    missing_srcs = [s for s in srcs if not os.path.exists(os.path.join(r'f:\~dev\rawrxd', s.replace('/', os.sep)))]
    log(f'RawrXD-Win32IDE missing in source list: {missing_srcs}')

# Apply core fixes
# A. Filter RAWR_ENGINE_SOURCES before add_executable
# Find: set_source_files_properties(${RAWR_ENGINE_ASM_SOURCES} ...)
# Add rawrxd_filter_missing_sources right before add_executable(RawrEngine
old_rawr = 'set_source_files_properties(${RAWR_ENGINE_ASM_SOURCES} PROPERTIES LANGUAGE ASM_MASM)\n\nadd_executable(RawrEngine'
new_rawr = 'set_source_files_properties(${RAWR_ENGINE_ASM_SOURCES} PROPERTIES LANGUAGE ASM_MASM)\nrawrxd_filter_missing_sources(RAWR_ENGINE_SOURCES)\nrawrxd_filter_missing_sources(RAWR_ENGINE_ASM_SOURCES)\n\nif(RAWR_ENGINE_SOURCES OR RAWR_ENGINE_ASM_SOURCES)\n    add_executable(RawrEngine'
if old_rawr in content:
    content = content.replace(old_rawr, new_rawr, 1)
    log('Added RAWR_ENGINE_SOURCES filter + guard')
else:
    log('WARNING: Could not find RawrEngine add_executable anchor')

# Close the if block
old_rawr_end = 'add_executable(RawrEngine ${RAWR_ENGINE_SOURCES} ${RAWR_ENGINE_ASM_SOURCES})'
new_rawr_end = 'add_executable(RawrEngine ${RAWR_ENGINE_SOURCES} ${RAWR_ENGINE_ASM_SOURCES})\nendif()'
if old_rawr_end in content:
    content = content.replace(old_rawr_end, new_rawr_end, 1)
    log('Closed RawrEngine if block')
else:
    log('WARNING: Could not find RawrEngine add_executable closing anchor')

# B. Filter GOLD_UNDERSCORE_SOURCES before add_executable(RawrXD_Gold
old_gold = 'add_executable(RawrXD_Gold ${GOLD_UNDERSCORE_SOURCES} ${ASM_KERNEL_SOURCES})'
if old_gold in content:
    content = content.replace(old_gold, 'rawrxd_filter_missing_sources(GOLD_UNDERSCORE_SOURCES)\nrawrxd_filter_missing_sources(ASM_KERNEL_SOURCES)\n\nif(GOLD_UNDERSCORE_SOURCES OR ASM_KERNEL_SOURCES)\n    add_executable(RawrXD_Gold ${GOLD_UNDERSCORE_SOURCES} ${ASM_KERNEL_SOURCES})\nendif()')
    log('Added GOLD_UNDERSCORE_SOURCES filter + guard')
else:
    log('WARNING: Could not find RawrXD_Gold add_executable anchor')

# C. Filter INFERENCE_ASM_SOURCES before target_sources(InferenceEngine
old_inf = '    set_source_files_properties(${INFERENCE_ASM_SOURCES} PROPERTIES LANGUAGE ASM_MASM)\n    target_sources(InferenceEngine PRIVATE ${INFERENCE_ASM_SOURCES})'
new_inf = '    rawrxd_filter_missing_sources(INFERENCE_ASM_SOURCES)\n    if(INFERENCE_ASM_SOURCES)\n    set_source_files_properties(${INFERENCE_ASM_SOURCES} PROPERTIES LANGUAGE ASM_MASM)\n    target_sources(InferenceEngine PRIVATE ${INFERENCE_ASM_SOURCES})\n    endif()'
if old_inf in content:
    content = content.replace(old_inf, new_inf, 1)
    log('Added INFERENCE_ASM_SOURCES filter + guard')
else:
    log('WARNING: Could not find InferenceEngine ASM anchor')

# D. Guard ReverseEngineering.cpp
old_rev = '        list(APPEND WIN32IDE_SOURCES src/modules/ReverseEngineering.cpp)'
new_rev = '        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/modules/ReverseEngineering.cpp")\n            list(APPEND WIN32IDE_SOURCES src/modules/ReverseEngineering.cpp)\n        endif()'
if old_rev in content:
    content = content.replace(old_rev, new_rev, 1)
    log('Guarded ReverseEngineering.cpp')
else:
    log('WARNING: Could not find ReverseEngineering.cpp anchor')

# Write modified CMakeLists.txt
with open(cmake_path, 'w', encoding='utf-8', errors='replace') as f:
    f.write(content)

log('\nDone writing CMakeLists.txt')
