import re

path = r'f:\~dev\rawrxd\CMakeLists.txt'
with open(path, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

# 1. Filter RAWR_ENGINE_SOURCES and RAWR_ENGINE_ASM_SOURCES before add_executable(RawrEngine)
content = content.replace(
    'set_source_files_properties(${RAWR_ENGINE_ASM_SOURCES} PROPERTIES LANGUAGE ASM_MASM)\n\nadd_executable(RawrEngine',
    'set_source_files_properties(${RAWR_ENGINE_ASM_SOURCES} PROPERTIES LANGUAGE ASM_MASM)\nrawrxd_filter_missing_sources(RAWR_ENGINE_SOURCES)\nrawrxd_filter_missing_sources(RAWR_ENGINE_ASM_SOURCES)\n\nadd_executable(RawrEngine'
)

# 2. Filter GOLD_UNDERSCORE_SOURCES and ASM_KERNEL_SOURCES before add_executable(RawrXD_Gold)
m = re.search(r'(# Remove duplicate stub files.*?)(add_executable\(RawrXD_Gold)', content, re.DOTALL)
if m:
    old = m.group(0)
    new = m.group(1) + 'rawrxd_filter_missing_sources(GOLD_UNDERSCORE_SOURCES)\nrawrxd_filter_missing_sources(ASM_KERNEL_SOURCES)\n\n' + m.group(2)
    content = content.replace(old, new, 1)

# 3. Filter INFERENCE_ASM_SOURCES before set_source_files_properties
content = content.replace(
    '    set_source_files_properties(${INFERENCE_ASM_SOURCES} PROPERTIES LANGUAGE ASM_MASM)\n    target_sources(InferenceEngine PRIVATE ${INFERENCE_ASM_SOURCES})',
    '    rawrxd_filter_missing_sources(INFERENCE_ASM_SOURCES)\n    set_source_files_properties(${INFERENCE_ASM_SOURCES} PROPERTIES LANGUAGE ASM_MASM)\n    target_sources(InferenceEngine PRIVATE ${INFERENCE_ASM_SOURCES})'
)

# 4. Guard RawrEngine add_executable
content = content.replace(
    'add_executable(RawrEngine ${RAWR_ENGINE_SOURCES} ${RAWR_ENGINE_ASM_SOURCES})',
    'if(RAWR_ENGINE_SOURCES OR RAWR_ENGINE_ASM_SOURCES)\n    add_executable(RawrEngine ${RAWR_ENGINE_SOURCES} ${RAWR_ENGINE_ASM_SOURCES})\nelse()\n    message(STATUS "[RAWRXD_BUILD_AUTHORITY_BASELINE_001] Skipping RawrEngine: no sources available")\nendif()'
)

# 5. Guard RawrXD_Gold add_executable
content = content.replace(
    'add_executable(RawrXD_Gold ${GOLD_UNDERSCORE_SOURCES} ${ASM_KERNEL_SOURCES})',
    'if(GOLD_UNDERSCORE_SOURCES OR ASM_KERNEL_SOURCES)\n    add_executable(RawrXD_Gold ${GOLD_UNDERSCORE_SOURCES} ${ASM_KERNEL_SOURCES})\nelse()\n    message(STATUS "[RAWRXD_BUILD_AUTHORITY_BASELINE_001] Skipping RawrXD_Gold: no sources available")\nendif()'
)

# 6. Guard ReverseEngineering.cpp append
content = content.replace(
    '        list(APPEND WIN32IDE_SOURCES src/modules/ReverseEngineering.cpp)',
    '        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/modules/ReverseEngineering.cpp")\n            list(APPEND WIN32IDE_SOURCES src/modules/ReverseEngineering.cpp)\n        endif()'
)

# 7. Guard all add_executable lines with hardcoded src/ paths (except Win32IDE which is already filtered)
lines = content.splitlines()
new_lines = []
i = 0
n = len(lines)
while i < n:
    line = lines[i]
    # Match add_executable with at least one hardcoded src/ or tests/ or certs/ path
    m = re.match(r'^(\s*)add_executable\((\w+)\s+((?:src/|tests/|certs/)[^ )]+(?:\s+(?:src/|tests/|certs/)[^ )]+)*)\)\s*$', line)
    if m and 'RawrXD-Win32IDE' not in m.group(2):
        indent = m.group(1)
        srcs = re.findall(r'(?:src/|tests/|certs/)[^ )]+', m.group(3))
        # Wrap with if(EXISTS) using first source
        guard = indent + 'if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/' + srcs[0] + '")'
        new_lines.append(guard)
        new_lines.append(line)
        i += 1
        # Absorb following lines that belong to this target until blank/new block
        while i < n and lines[i].strip() and not lines[i].strip().startswith('if(') and not lines[i].strip().startswith('endif()'):
            new_lines.append(lines[i])
            i += 1
        new_lines.append(indent + 'endif()')
        # skip blank line if present
        if i < n and lines[i].strip() == '':
            new_lines.append(lines[i])
            i += 1
        continue
    new_lines.append(line)
    i += 1
content = '\n'.join(new_lines)

with open(path, 'w', encoding='utf-8', errors='replace') as f:
    f.write(content)

print('Done.')
