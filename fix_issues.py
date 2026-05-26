import os
import glob
import re

# Fix LoadLibraryExW flag combo
gpu_files = glob.glob(r"D:\rawrxd\src\**\*.cpp", recursive=True)
for f in gpu_files:
    try:
        with open(f, 'r', encoding='utf-8') as file:
            content = file.read()
            if 'LOAD_WITH_ALTERED_SEARCH_PATH' in content and 'LOAD_LIBRARY_SEARCH_DEFAULT_DIRS' in content:
                print(f"Applying fix to {f}...")
                content = content.replace('LOAD_WITH_ALTERED_SEARCH_PATH | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS', 'LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32')
                with open(f, 'w', encoding='utf-8') as out_file:
                    out_file.write(content)
    except Exception as e:
        pass

# Append END to MASM files
asm_files = glob.glob(r"D:\rawrxd\src\asm\*.asm", recursive=True)
count = 0
for f in asm_files:
    with open(f, 'r', encoding='utf-8') as file:
        content = file.read()
    
    if 'END' not in content:
        with open(f, 'a', encoding='utf-8') as file:
            file.write('\nEND\n')
        count += 1
        print(f"Appended END to {f}")
print(f"Fixed {count} MASM files.")

