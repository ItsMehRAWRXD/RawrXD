import os
import re
import glob

def ensure_stub(path):
    dir_path = os.path.dirname(path)
    if dir_path and not os.path.exists(dir_path):
        os.makedirs(dir_path, exist_ok=True)
    if not os.path.exists(path):
        ext = os.path.splitext(path)[1].lower()
        with open(path, 'w') as f:
            if ext in ('.h', '.hpp'):
                f.write('#pragma once\n// [RAWRXD_BUILD_AUTHORITY_BASELINE_001] stub\n')
            elif ext == '.asm':
                f.write('; [RAWRXD_BUILD_AUTHORITY_BASELINE_001] stub\n')
            else:
                f.write('// [RAWRXD_BUILD_AUTHORITY_BASELINE_001] stub\n')

def process_cmake_file(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Match source file references like src/deep2/file.cpp, src/core/file.hpp, src/asm/file.asm
    pattern = re.compile(r'\b(src/[\w/]+\.(?:cpp|c|hpp|h|asm))\b')
    matches = pattern.findall(content)
    
    base_dir = r'F:\~dev\rawrxd'
    unique = set(matches)
    print(f"Processing {filepath}: found {len(unique)} unique source refs")
    for m in unique:
        full_path = os.path.join(base_dir, m.replace('/', '\\'))
        ensure_stub(full_path)

# Process main CMakeLists.txt
process_cmake_file(r'F:\~dev\rawrxd\CMakeLists.txt')

# Process fragment cmake files
for frag in glob.glob(r'F:\~dev\rawrxd\cmake\*.cmake'):
    process_cmake_file(frag)

# Also process subdir CMakeLists.txt files that might add targets
for sub in glob.glob(r'F:\~dev\rawrxd\src\**\CMakeLists.txt', recursive=True):
    process_cmake_file(sub)

print("Done.")
