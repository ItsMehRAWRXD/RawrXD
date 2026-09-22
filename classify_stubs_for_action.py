import csv, sys, os, re

csv.field_size_limit(sys.maxsize)

# Load all stubs from inventory
stubs = {}  # fname -> list of paths
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
    cmake_content = f.read()
    cmake_lines = cmake_content.splitlines()

# Find which stub filenames are referenced in CMakeLists.txt
referenced = set()
not_referenced = set()

for fname in stubs:
    found = False
    for line in cmake_lines:
        if fname in line:
            found = True
            break
    if found:
        referenced.add(fname)
    else:
        not_referenced.add(fname)

# Classify stubs
a_stubs = set()
c_stubs = set()
unknown_stubs = set()

for fname in stubs:
    stub_paths = stubs[fname]
    if any('\\certs\\' in p or '\\tests\\' in p for p in stub_paths):
        a_stubs.add(fname)
    elif real_files_by_name.get(fname):
        c_stubs.add(fname)
    else:
        unknown_stubs.add(fname)

# Now classify by CMake reference
# Group 1: Safe to delete (not in CMake)
group1_delete = not_referenced  # 215 stubs

# Group 2: Class A stubs in CMake (remove add_executable targets)
group2_a_in_cmake = a_stubs & referenced

# Group 3: Unknown stubs in CMake - need to check for real counterpart
group3_unknown_in_cmake = unknown_stubs & referenced

# For group 3: split into those with and without real counterpart
group3a_fix_ref = set()  # have real counterpart elsewhere
group3b_remove_ref = set()  # no real counterpart

for fname in group3_unknown_in_cmake:
    if fname in real_files_by_name:
        group3a_fix_ref.add(fname)
    else:
        group3b_remove_ref.add(fname)

print(f"Group 1 (safe to delete, not in CMake): {len(group1_delete)}")
print(f"Group 2 (Class A stubs in CMake): {len(group2_a_in_cmake)}")
print(f"Group 3a (unknown in CMake with real counterpart): {len(group3a_fix_ref)}")
print(f"Group 3b (unknown in CMake no real counterpart): {len(group3b_remove_ref)}")
print(f"Total: {len(group1_delete) + len(group2_a_in_cmake) + len(group3a_fix_ref) + len(group3b_remove_ref)}")

# Write group1 deletion list
with open('group1_delete.txt', 'w', encoding='utf-8') as f:
    for fname in sorted(group1_delete):
        for path in stubs[fname]:
            f.write(path + '\n')

# Write group3 analysis
with open('group3_analysis.txt', 'w', encoding='utf-8') as f:
    f.write("Group 3a: Fix reference (real counterpart exists)\n")
    f.write("="*80 + "\n")
    for fname in sorted(group3a_fix_ref):
        f.write(f"{fname}\n")
        f.write(f"  Stub: {stubs[fname]}\n")
        f.write(f"  Real: {real_files_by_name[fname]}\n\n")

    f.write("\nGroup 3b: Remove from CMake (no real counterpart)\n")
    f.write("="*80 + "\n")
    for fname in sorted(group3b_remove_ref):
        f.write(f"{fname}\n")
        f.write(f"  Stub: {stubs[fname]}\n\n")

# Group 2 analysis: write add_executable lines that reference Class A stubs
with open('group2_a_cmake_lines.txt', 'w', encoding='utf-8') as f:
    f.write("Group 2 (Class A stubs in CMake - need to remove add_executable targets):\n")
    f.write("="*80 + "\n\n")
    for fname in sorted(group2_a_in_cmake):
        f.write(f"{fname}\n")
        for i, line in enumerate(cmake_lines, 1):
            if fname in line:
                f.write(f"  Line {i}: {line}\n")
        f.write("\n")

print("Written group1_delete.txt, group2_a_cmake_lines.txt, group3_analysis.txt")
