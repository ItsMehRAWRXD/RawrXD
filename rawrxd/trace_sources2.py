import re, shlex

with open('CMakeLists.txt','r') as f:
    content = f.read()
    lines = content.splitlines()

# Parse SOURCES block (simple approach: find set(SOURCES and collect until matching close paren at start of line)
def parse_set(lines, start_idx):
    items = []
    i = start_idx
    # assume line i contains 'set(VARNAME'
    line = lines[i]
    # count open parens on this line
    depth = line.count('(') - line.count(')')
    i += 1
    while i < len(lines):
        l = lines[i].strip()
        if l.startswith('#'):
            i += 1
            continue
        # count parens
        depth += l.count('(') - l.count(')')
        if depth == 0:
            # last line, check if item before )
            item_part = l.split(')')[0].strip()
            if item_part:
                items.append(item_part)
            break
        else:
            items.append(l.split('#')[0].strip())
        i += 1
    return items, i

start = None
for i,l in enumerate(lines):
    if l.strip().startswith('set(SOURCES'):
        start = i
        break

sources_items, end_idx = parse_set(lines, start)
# Clean items
sources = [it for it in sources_items if it and not it.startswith('#')]
print(f'SOURCES count from parse: {len(sources)}')

# Trace SOURCES operations
current_sources = list(sources)
for i,l in enumerate(lines):
    stripped = l.strip()
    if i == start:
        continue
    if stripped.startswith('list(REMOVE_ITEM SOURCES'):
        block_lines = [stripped]
        j = i+1
        depth = stripped.count('(') - stripped.count(')')
        while j < len(lines) and depth > 0:
            sl = lines[j].strip()
            depth += sl.count('(') - sl.count(')')
            block_lines.append(sl)
            j += 1
        block = ' '.join(block_lines)
        m = re.search(r'list\(REMOVE_ITEM SOURCES\s+(.+)\)', block, re.DOTALL)
        if m:
            items = shlex.split(m.group(1))
            for it in items:
                it = it.strip()
                if it.startswith('#'): continue
                if it in current_sources:
                    current_sources.remove(it)
    elif stripped.startswith('list(FILTER SOURCES EXCLUDE REGEX'):
        m = re.search(r'list\(FILTER SOURCES EXCLUDE REGEX\s+(.+)\)', stripped)
        if m:
            pattern = m.group(1).strip().strip('"').strip("'")
            compiled = re.compile(pattern)
            before = len(current_sources)
            current_sources = [s for s in current_sources if not compiled.search(s)]
            after = len(current_sources)
            if after != before:
                print(f'Line {i+1}: FILTER SOURCES removed {before-after} items. Remaining: {after}')

print(f'SOURCES count before RAWR_ENGINE_SOURCES set: {len(current_sources)}')
if len(current_sources) == 0:
    print('SOURCES IS EMPTY BEFORE RAWR_ENGINE_SOURCES!')
else:
    print('First 5 SOURCES:', current_sources[:5])
