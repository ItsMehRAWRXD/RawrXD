import re, os

path = r'f:\~dev\rawrxd\CMakeLists.txt'
with open(path, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

# Backup
with open(path + '.bak_final2', 'w', encoding='utf-8', errors='replace') as f:
    f.write(content)

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

# 7. Parse file and for every if(BUILD_...) or if(BUILD_... AND ...) block,
#    check if it contains an add_executable with hardcoded src/ paths.
#    If the source file does NOT exist, append AND EXISTS condition to the if() line.
lines = content.splitlines()
new_lines = []
i = 0
n = len(lines)
while i < n:
    line = lines[i]
    # Match if(BUILD_... ) at any indentation
    m = re.match(r'^(\s*)if\((BUILD_\w+.*?)(\)\s*)$', line)
    if m and 'EXISTS' not in line:
        indent = m.group(1)
        build_opt = m.group(2)
        closing = m.group(3)
        block_start = i
        # find matching endif()
        depth = 1
        j = i + 1
        while j < n and depth > 0:
            l = lines[j].strip()
            if l.startswith('if(') and not l.startswith('if(#'):
                depth += 1
            elif l == 'endif()':
                depth -= 1
            j += 1
        # block lines are i+1 .. j-2 (excluding endif())
        block_text = '\n'.join(lines[i+1:j-1])
        # Find add_executable inside block with hardcoded src/ paths
        add_execs = re.findall(r'add_executable\(\w+\s+((?:src/|tests/|certs/)[^\)]+)\)', block_text)
        missing_src = None
        for ae in add_execs:
            # extract first path
            first_path = re.search(r'(?:src/|tests/|certs/)[^\s\)]+', ae)
            if first_path:
                p = first_path.group(0)
                full = os.path.join(r'f:\~dev\rawrxd', p.replace('/', os.sep))
                if not os.path.exists(full):
                    missing_src = p
                    break
        if missing_src:
            # Modify the if() line to include AND EXISTS condition
            new_line = f'{indent}if({build_opt} AND EXISTS "${{CMAKE_CURRENT_SOURCE_DIR}}/{missing_src}"){closing}'
            new_lines.append(new_line)
            i += 1
            continue
    new_lines.append(line)
    i += 1
content = '\n'.join(new_lines)

with open(path, 'w', encoding='utf-8', errors='replace') as f:
    f.write(content)

print('Done.')
