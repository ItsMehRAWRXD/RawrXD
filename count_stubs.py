import csv, sys, os
csv.field_size_limit(sys.maxsize)

a = c = unknown = 0
a_paths = []
c_paths = []
unknown_paths = []

# Build real file map
real_files_by_name = {}
with open('rawrxd_inventory.csv', newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        path = row['FullName']
        lines = int(row['Lines'])
        if lines > 1:
            fname = os.path.basename(path)
            real_files_by_name.setdefault(fname, []).append(path)

with open('rawrxd_inventory.csv', newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        path = row['FullName']
        lines = int(row['Lines'])
        first = row['FirstLine']
        if lines == 1 and first == '// [RAWRXD_BUILD_AUTHORITY_BASELINE_001] stub':
            fname = os.path.basename(path)
            reals = [p for p in real_files_by_name.get(fname, []) if p != path]
            if '\certs\\' in path or '\tests\\' in path:
                a += 1
                a_paths.append(path)
            elif reals:
                c += 1
                c_paths.append(path)
            else:
                unknown += 1
                unknown_paths.append(path)

print(f'Total stubs: {a+c+unknown}')
print(f'Class A (certs/tests): {a}')
print(f'Class C (dual, real counterpart exists): {c}')
print(f'Class UNKNOWN: {unknown}')

# Write unknown list for analysis
with open('unknown_stubs.txt', 'w', encoding='utf-8') as f:
    for p in unknown_paths:
        f.write(p + '\n')
