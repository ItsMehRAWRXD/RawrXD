import csv, re, os
from collections import defaultdict

# Step 1: Load C-class stubs from inventory
stub_files = []
with open('rawrxd_inventory.csv', newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        path = row['relative_path']
        lines = int(row['line_count'])
        first = row['first_line']
        if lines == 1 and first == '// [RAWRXD_BUILD_AUTHORITY_BASELINE_001] stub':
            stub_files.append(path)

# Build map of real files by filename
real_files_by_name = defaultdict(list)
with open('rawrxd_inventory.csv', newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        path = row['relative_path']
        lines = int(row['line_count'])
        if lines > 1:
            fname = os.path.basename(path)
            real_files_by_name[fname].append(path)

# Identify C-class: stub AND real counterpart exists
class_c = []
for stub_path in stub_files:
    fname = os.path.basename(stub_path)
    reals = [p for p in real_files_by_name.get(fname, []) if p != stub_path]
    if reals:
        class_c.append((stub_path, reals))

# Step 2: Check which appear in CMakeLists.txt
with open('rawrxd/CMakeLists.txt', 'r', encoding='utf-8') as f:
    cmake_text = f.read()

found_in_cmake = []
not_in_cmake = []
for stub_path, reals in class_c:
    inner = stub_path[len('rawrxd/'):] if stub_path.startswith('rawrxd/') else stub_path
    if inner in cmake_text:
        found_in_cmake.append((stub_path, inner, reals))
    else:
        not_in_cmake.append((stub_path, inner, reals))

# Write results to file in UTF-8
with open('c_stubs_results.txt', 'w', encoding='utf-8') as out:
    out.write(f"Total C-class stubs identified: {len(class_c)}\n\n")
    out.write(f"C-class stubs FOUND in CMakeLists.txt source lists ({len(found_in_cmake)}):\n")
    for sp, inner, reals in sorted(found_in_cmake):
        out.write(f"  STUB: {sp}\n")
        for r in reals:
            out.write(f"    -> REAL: {r}\n")
    out.write(f"\nC-class stubs NOT in CMakeLists.txt ({len(not_in_cmake)}):\n")
    for sp, inner, reals in sorted(not_in_cmake):
        out.write(f"  STUB: {sp}\n")

print(f"Done. C-class={len(class_c)}, In CMake={len(found_in_cmake)}, Not in CMake={len(not_in_cmake)}")
