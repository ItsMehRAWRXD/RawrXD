with open(r'f:\~dev\rawrxd\CMakeLists.txt', 'r', encoding='utf-8', newline='') as f:
    lines = f.readlines()

count_on = 0
count_off = 0
new_lines = []
for line in lines:
    stripped = line.strip()
    if stripped.startswith('option(BUILD_DEEP2_') and stripped.endswith('ON)'):
        new_line = line.rstrip('ON)\r\n') + 'OFF)\r\n'
        # Be more precise
        new_line = line.rsplit('ON)', 1)[0] + 'OFF)'
        if line.endswith('\r\n'):
            new_line += '\r\n'
        elif line.endswith('\n'):
            new_line += '\n'
        new_lines.append(new_line)
        count_on += 1
    else:
        new_lines.append(line)
        if stripped.startswith('option(BUILD_DEEP2_') and stripped.endswith('OFF)'):
            count_off += 1

with open(r'f:\~dev\rawrxd\CMakeLists.txt', 'w', encoding='utf-8', newline='') as f:
    f.writelines(new_lines)

print(f'Fixed ON->OFF: {count_on}')
print(f'Already OFF: {count_off}')
