import csv, sys, os, re

csv.field_size_limit(sys.maxsize)

# Load all stubs from inventory
stubs = []
stub_names = set()
with open('rawrxd_inventory.csv', newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        path = row['FullName']
        lines = int(row['Lines'])
        first = row['FirstLine']
        if lines == 1 and first == '// [RAWRXD_BUILD_AUTHORITY_BASELINE_001] stub':
            stubs.append(path)
            stub_names.add(os.path.basename(path))

print(f"Total stubs: {len(stubs)}")

# Read CMakeLists.txt and find lines that reference stub filenames
# Normalize stub filenames for matching
stub_in_cmake = {}
stub_not_in_cmake = []

with open('rawrxd/CMakeLists.txt', 'r', encoding='utf-8') as f:
    cmake_content = f.read()
    cmake_lines = cmake_content.splitlines()

for stub_path in stubs:
    fname = os.path.basename(stub_path)
    # Look for the filename in CMakeLists.txt
    found = False
    for i, line in enumerate(cmake_lines, 1):
        if fname in line:
            found = True
            stub_in_cmake.setdefault(stub_path, []).append((i, line.strip()))
    if not found:
        stub_not_in_cmake.append(stub_path)

print(f"Stubs referenced in CMakeLists.txt: {len(stub_in_cmake)}")
print(f"Stubs NOT referenced in CMakeLists.txt: {len(stub_not_in_cmake)}")

# Write results
with open('unknown_stub_cmake_analysis.txt', 'w', encoding='utf-8') as f:
    f.write(f"Total stubs: {len(stubs)}\n")
    f.write(f"Stubs referenced in CMakeLists.txt: {len(stub_in_cmake)}\n")
    f.write(f"Stubs NOT referenced in CMakeLists.txt: {len(stub_not_in_cmake)}\n\n")
    
    f.write("="*80 + "\n")
    f.write("STUBS REFERENCED IN CMAKE (need fix or are okay):\n")
    f.write("="*80 + "\n\n")
    for stub_path, lines in sorted(stub_in_cmake.items()):
        f.write(f"{stub_path}\n")
        for line_no, line_text in lines:
            f.write(f"  Line {line_no}: {line_text}\n")
        f.write("\n")
    
    f.write("="*80 + "\n")
    f.write("STUBS NOT IN CMAKE (safe to delete):\n")
    f.write("="*80 + "\n\n")
    for stub_path in sorted(stub_not_in_cmake):
        f.write(f"{stub_path}\n")

print("Results written to unknown_stub_cmake_analysis.txt")
