import csv, sys, os, re

csv.field_size_limit(sys.maxsize)

# Load all stubs from inventory
stubs = {}
with open('rawrxd_inventory.csv', newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        path = row['FullName']
        lines = int(row['Lines'])
        first = row['FirstLine']
        if lines == 1 and first == '// [RAWRXD_BUILD_AUTHORITY_BASELINE_001] stub':
            fname = os.path.basename(path)
            stubs.setdefault(fname, []).append(path)

# Build real file map (excluding stubs)
real_files_by_name = {}
with open('rawrxd_inventory.csv', newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        path = row['FullName']
        lines = int(row['Lines'])
        first = row['FirstLine']
        if lines > 1:
            fname = os.path.basename(path)
            real_files_by_name.setdefault(fname, []).append(path)

# Read CMakeLists.txt
with open('rawrxd/CMakeLists.txt', 'r', encoding='utf-8') as f:
    cmake_lines = f.readlines()

# Find stub references in CMake
cmake_stub_lines = {}  # fname -> [(line_no, line_text)]
for i, line in enumerate(cmake_lines, 1):
    for fname in stubs:
        # Match the filename as a standalone token or path component
        if re.search(re.escape(fname), line):
            cmake_stub_lines.setdefault(fname, []).append((i, line.rstrip('\n')))

# Categorize stubs
referenced_in_cmake = set(cmake_stub_lines.keys())
not_referenced_in_cmake = set(stubs.keys()) - referenced_in_cmake

# For stubs referenced in CMake, check if real file exists elsewhere
referenced_with_real_counterpart = []
referenced_without_real_counterpart = []

for fname in sorted(referenced_in_cmake):
    real_counterparts = real_files_by_name.get(fname, [])
    if real_counterparts:
        referenced_with_real_counterpart.append((fname, real_counterparts))
    else:
        referenced_without_real_counterpart.append(fname)

print(f"Total unique stub filenames: {len(stubs)}")
print(f"Referenced in CMakeLists.txt: {len(referenced_in_cmake)}")
print(f"  - With real counterpart elsewhere: {len(referenced_with_real_counterpart)}")
print(f"  - Without real counterpart: {len(referenced_without_real_counterpart)}")
print(f"NOT referenced in CMakeLists.txt: {len(not_referenced_in_cmake)}")

# Write detailed analysis
with open('stub_cmake_detailed_analysis.txt', 'w', encoding='utf-8') as f:
    f.write(f"Total unique stub filenames: {len(stubs)}\n")
    f.write(f"Referenced in CMakeLists.txt: {len(referenced_in_cmake)}\n")
    f.write(f"  - With real counterpart elsewhere: {len(referenced_with_real_counterpart)}\n")
    f.write(f"  - Without real counterpart: {len(referenced_without_real_counterpart)}\n")
    f.write(f"NOT referenced in CMakeLists.txt: {len(not_referenced_in_cmake)}\n\n")

    f.write("="*80 + "\n")
    f.write("STUBS REFERENCED IN CMAKE WITH REAL COUNTERPART (fix reference):\n")
    f.write("="*80 + "\n\n")
    for fname, real_paths in referenced_with_real_counterpart:
        f.write(f"{fname}\n")
        f.write(f"  Stub paths: {stubs[fname]}\n")
        f.write(f"  Real paths: {real_paths}\n")
        f.write(f"  CMake lines:\n")
        for line_no, line_text in cmake_stub_lines[fname]:
            f.write(f"    {line_no}: {line_text}\n")
        f.write("\n")

    f.write("="*80 + "\n")
    f.write("STUBS REFERENCED IN CMAKE WITHOUT REAL COUNTERPART (remove from CMake):\n")
    f.write("="*80 + "\n\n")
    for fname in referenced_without_real_counterpart:
        f.write(f"{fname}\n")
        f.write(f"  Stub paths: {stubs[fname]}\n")
        f.write(f"  CMake lines:\n")
        for line_no, line_text in cmake_stub_lines[fname]:
            f.write(f"    {line_no}: {line_text}\n")
        f.write("\n")

    f.write("="*80 + "\n")
    f.write("STUBS NOT IN CMAKE (safe to delete):\n")
    f.write("="*80 + "\n\n")
    for fname in sorted(not_referenced_in_cmake):
        f.write(f"{fname}\n")
        f.write(f"  Stub paths: {stubs[fname]}\n\n")

print("Detailed analysis written to stub_cmake_detailed_analysis.txt")
