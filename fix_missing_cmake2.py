import os, re

CMAKE = "f:/~dev/rawrxd/CMakeLists.txt"
ROOT = "f:/~dev/rawrxd"

with open(CMAKE, "r", encoding="utf-8") as f:
    lines = f.readlines()

i = 0
out = []
while i < len(lines):
    line = lines[i]
    m = re.match(r'^(option\(BUILD_[A-Z0-9_]+\s+"[^"]*"\s+ON\)\s*)$', line.strip())
    if m:
        option_line = line
        j = i + 1
        # collect block until endif()
        block_lines = []
        while j < len(lines) and not lines[j].strip().startswith("endif()"):
            block_lines.append(lines[j])
            j += 1
        endif_line = lines[j] if j < len(lines) else ""
        # Determine if add_executable references a missing cpp/asm file
        missing = False
        missing_file = ""
        for bl in block_lines:
            mm = re.search(r'add_executable\s*\(\s*\w+\s+((?:src/|certs/|tests/)[^\s)]+)\)', bl)
            if mm:
                fpath = mm.group(1)
                full = os.path.join(ROOT, fpath.replace('/', os.sep))
                if not os.path.exists(full):
                    missing = True
                    missing_file = fpath
                    break
        if missing:
            # replace if(BUILD_...) with if(0)
            for idx in range(len(block_lines)):
                if re.match(r'^if\(BUILD_[A-Z0-9_]+\)\s*$', block_lines[idx].strip()):
                    block_lines[idx] = block_lines[idx].rstrip().rstrip(')').rstrip('(') + 'if(0)  # [RAWRXD_BUILD_SOURCE_INTEGRITY_001] Missing: ' + missing_file + '\n'
                    break
        out.append(option_line)
        out.extend(block_lines)
        out.append(endif_line)
        i = j + 1
        continue
    out.append(line)
    i += 1

with open(CMAKE, "w", encoding="utf-8") as f:
    f.writelines(out)

print("Done")
