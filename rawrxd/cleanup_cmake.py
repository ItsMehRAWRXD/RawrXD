import re, os

root = 'f:\\~dev\\rawrxd'
with open('CMakeLists.txt', 'r', encoding='utf-8') as f:
    lines = f.read().splitlines()

out = []
i = 0
n = len(lines)
while i < n:
    line = lines[i]
    m = re.match(r'^(\s*add_executable\s*\(\s*\w+\s+EXCLUDE_FROM_ALL\s*)$', line)
    if m:
        block = [line]
        j = i + 1
        while j < n:
            block.append(lines[j])
            if re.match(r'^\s*\)', lines[j]):
                break
            j += 1
        has = False
        for bl in block:
            if re.search(r'\.(cpp|c|asm)\s*$', bl) and not bl.strip().startswith('#'):
                has = True
                break
        if has:
            out.extend(block)
        else:
            out.append('        # REMOVED_EMPTY_TARGET: ' + line.strip())
        i = j + 1
        continue

    stripped = line.strip()
    if stripped.startswith('#'):
        out.append(line)
        i += 1
        continue

    sm = re.match(r'^(\s*)(src/[^\s#]+\.(?:cpp|c|asm))\s*$', stripped)
    if sm:
        fpath = os.path.join(root, sm.group(2))
        if os.path.exists(fpath):
            out.append(line)
        else:
            out.append(sm.group(1) + '# REMOVED_MISSING: ' + sm.group(2))
        i += 1
        continue

    out.append(line)
    i += 1

with open('CMakeLists.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(out))

print('Done. Lines:', len(out))
