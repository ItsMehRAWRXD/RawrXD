import re
import os

cmake_file = r"F:\rawrxd\CMakeLists.txt"
base_dir = r"F:\rawrxd"

with open(cmake_file, 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

# Find all add_executable blocks
pattern = r'add_executable\((\S+)(.*?)\)'
matches = re.finditer(pattern, content, re.DOTALL)

missing_targets = []
for match in matches:
    target = match.group(1)
    sources_text = match.group(2)
    
    # Extract source files
    sources = re.findall(r'(\S+\.(cpp|c|h|asm))', sources_text)
    
    # Check if any source doesn't exist
    missing = []
    for src in sources:
        src_path = os.path.join(base_dir, src[0])
        if not os.path.exists(src_path):
            missing.append(src[0])
    
    if missing:
        missing_targets.append((target, missing))

print("Targets with missing sources:")
for target, missing in missing_targets:
    print(f"  {target}:")
    for src in missing:
        print(f"    - {src}")
print(f"\nTotal: {len(missing_targets)} targets")
