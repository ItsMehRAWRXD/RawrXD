import re, os

# Read missing files
with open(r'f:\~dev\missing_sources.txt', 'r', encoding='utf-8', errors='replace') as f:
    missing_files = [line.strip().replace('/', os.sep) for line in f if line.strip()]

print(f'Processing {len(missing_files)} missing files')

# Read CMakeLists.txt
cmake_path = r'f:\~dev\rawrxd\CMakeLists.txt'
with open(cmake_path, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

# Backup
with open(cmake_path + '.bak_fix_options', 'w', encoding='utf-8', errors='replace') as f:
    f.write(content)

# Find all option(BUILD_... ON) blocks and their associated if(BUILD_...) blocks
# Strategy: For each missing file, find which BUILD_ option controls the add_executable that references it.
# We'll do this by scanning for patterns.

# Extract all option lines
option_pattern = re.compile(r'^option\((BUILD_\w+)\s+"([^"]+)"\s+(ON|OFF)\)', re.MULTILINE)
options = option_pattern.findall(content)
print(f'Found {len(options)} BUILD_ options')

# For each missing file, find the controlling option
modified_options = set()
for mf in missing_files:
    # Normalize path for search
    search_path = mf.replace(os.sep, '/')
    # Find the add_executable block that references this file
    # We look for add_executable(...) followed by the file path
    # But we need to find which option controls this block.
    # Simpler: find the if(BUILD_*) block that contains this file reference.
    pattern = re.compile(r'if\((BUILD_\w+).*?\n.*?add_executable\([^)]+' + re.escape(search_path) + r'[^)]*\)', re.DOTALL)
    match = pattern.search(content)
    if match:
        opt_name = match.group(1)
        modified_options.add(opt_name)
        print(f'  {mf} -> controlled by {opt_name}')
    else:
        # Try without add_executable (target_sources, etc.)
        pattern2 = re.compile(r'if\((BUILD_\w+).*?' + re.escape(search_path), re.DOTALL)
        match2 = pattern2.search(content)
        if match2:
            opt_name = match2.group(1)
            modified_options.add(opt_name)
            print(f'  {mf} -> controlled by {opt_name} (indirect)')
        else:
            print(f'  {mf} -> NO CONTROLLING OPTION FOUND')

print(f'\nWill modify {len(modified_options)} options from ON to OFF:')
for opt in sorted(modified_options):
    print(f'  {opt}')

# Now modify the option defaults in content
for opt_name in modified_options:
    # Replace option(NAME "desc" ON) with option(NAME "desc" OFF)
    old = f'option({opt_name} '
    # Use regex to be safe
    content = re.sub(
        rf'^option\({re.escape(opt_name)}\s+"([^"]*)"\s+ON\)',
        f'option({opt_name} "\\1" OFF)',
        content,
        flags=re.MULTILINE
    )

# Also handle the core targets that are NOT controlled by BUILD_* options:
# 1. RawrEngine (line ~3409) - add rawrxd_filter_missing_sources
# 2. RawrXD_Gold (line ~3770) - add rawrxd_filter_missing_sources  
# 3. InferenceEngine ASM (line ~5457) - add rawrxd_filter_missing_sources
# 4. RawrXD-Win32IDE (line ~7387) - ReverseEngineering.cpp guard

# 1. Filter RAWR_ENGINE_SOURCES and RAWR_ENGINE_ASM_SOURCES
content = content.replace(
    'set_source_files_properties(${RAWR_ENGINE_ASM_SOURCES} PROPERTIES LANGUAGE ASM_MASM)\n\nadd_executable(RawrEngine',
    'set_source_files_properties(${RAWR_ENGINE_ASM_SOURCES} PROPERTIES LANGUAGE ASM_MASM)\nrawrxd_filter_missing_sources(RAWR_ENGINE_SOURCES)\nrawrxd_filter_missing_sources(RAWR_ENGINE_ASM_SOURCES)\n\nif(RAWR_ENGINE_SOURCES OR RAWR_ENGINE_ASM_SOURCES)\n    add_executable(RawrEngine'
)
# Need to close the if block after add_executable line... find the next blank line or comment
# Actually just add endif() after add_executable line
content = content.replace(
    'add_executable(RawrEngine ${RAWR_ENGINE_SOURCES} ${RAWR_ENGINE_ASM_SOURCES})',
    'add_executable(RawrEngine ${RAWR_ENGINE_SOURCES} ${RAWR_ENGINE_ASM_SOURCES})\nendif()'
)

# 2. Filter GOLD_UNDERSCORE_SOURCES
m = re.search(r'(# Remove duplicate stub files.*?)(add_executable\(RawrXD_Gold)', content, re.DOTALL)
if m:
    old = m.group(0)
    new = m.group(1) + 'rawrxd_filter_missing_sources(GOLD_UNDERSCORE_SOURCES)\nrawrxd_filter_missing_sources(ASM_KERNEL_SOURCES)\n\nif(GOLD_UNDERSCORE_SOURCES OR ASM_KERNEL_SOURCES)\n    ' + m.group(2)
    content = content.replace(old, new, 1)
content = content.replace(
    'add_executable(RawrXD_Gold ${GOLD_UNDERSCORE_SOURCES} ${ASM_KERNEL_SOURCES})',
    'add_executable(RawrXD_Gold ${GOLD_UNDERSCORE_SOURCES} ${ASM_KERNEL_SOURCES})\nendif()'
)

# 3. Filter INFERENCE_ASM_SOURCES
content = content.replace(
    '    set_source_files_properties(${INFERENCE_ASM_SOURCES} PROPERTIES LANGUAGE ASM_MASM)\n    target_sources(InferenceEngine PRIVATE ${INFERENCE_ASM_SOURCES})',
    '    rawrxd_filter_missing_sources(INFERENCE_ASM_SOURCES)\n    if(INFERENCE_ASM_SOURCES)\n    set_source_files_properties(${INFERENCE_ASM_SOURCES} PROPERTIES LANGUAGE ASM_MASM)\n    target_sources(InferenceEngine PRIVATE ${INFERENCE_ASM_SOURCES})\n    endif()'
)

# 4. Guard ReverseEngineering.cpp append in WIN32IDE
content = content.replace(
    '        list(APPEND WIN32IDE_SOURCES src/modules/ReverseEngineering.cpp)',
    '        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/modules/ReverseEngineering.cpp")\n            list(APPEND WIN32IDE_SOURCES src/modules/ReverseEngineering.cpp)\n        endif()'
)

# Also handle rawr_globals.asm which is referenced in MASM_OBJECTS (line ~4642)
# and in ASM_KERNEL_SOURCES (line ~1924)
# It's listed directly in ASM_KERNEL_SOURCES - when we filter ASM_KERNEL_SOURCES for Gold, it should be removed.
# For MASM_OBJECTS block at line ~4642, we need to guard or filter it.
# Let's find the MASM_OBJECTS block
masm_pattern = re.compile(r'(set\(MASM_OBJECTS\s+.*?\))', re.DOTALL)
masm_match = masm_pattern.search(content)
if masm_match:
    old_masm = masm_match.group(1)
    # Filter the MASM_OBJECTS list
    lines = old_masm.splitlines()
    new_lines = [lines[0]]
    for line in lines[1:]:
        stripped = line.strip()
        if stripped.startswith('src/'):
            path = stripped.rstrip(')')
            # Check if exists
            full = os.path.join(r'f:\~dev\rawrxd', path.replace('/', os.sep))
            if os.path.exists(full):
                new_lines.append(line)
        else:
            new_lines.append(line)
    new_masm = '\n'.join(new_lines)
    content = content.replace(old_masm, new_masm)
    print('\nFiltered MASM_OBJECTS block')

with open(cmake_path, 'w', encoding='utf-8', errors='replace') as f:
    f.write(content)

print('\nDone! Modified CMakeLists.txt')
