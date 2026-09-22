import re

with open('F:/~dev/rawrxd/CMakeLists.txt', 'r', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

i = 0
changes = 0
while i < len(lines):
    line = lines[i]
    m = re.match(r'^(\s*)set\(ASM_([A-Z0-9_]+)_SRC\s+\"(.+?)\"\)', line)
    if m:
        indent = m.group(1)
        var_name = m.group(2)
        # Scan forward to find add_custom_command block for this var
        start_idx = i
        end_idx = None
        j = i + 1
        while j < len(lines):
            if 'add_custom_command(' in lines[j] and f'ASM_{var_name}_OBJ' in lines[j]:
                # Found start of add_custom_command for this var
                # Find closing ) considering nesting
                paren_depth = 0
                k = j
                found_start = False
                while k < len(lines):
                    for ch in lines[k]:
                        if ch == '(':
                            paren_depth += 1
                            found_start = True
                        elif ch == ')':
                            paren_depth -= 1
                            if found_start and paren_depth == 0:
                                end_idx = k
                                break
                    if end_idx is not None:
                        break
                    k += 1
                break
            j += 1

        if end_idx is not None:
            # Extract the block from start_idx to end_idx
            block_lines = lines[start_idx:end_idx+1]
            block_text = ''.join(block_lines)

            # Check if already wrapped
            if 'if(EXISTS' not in block_text:
                # Wrap it
                # Determine if block already has blank lines around it; preserve them
                inner = block_text.rstrip('\n')
                wrapped = f'{indent}if(EXISTS "${{ASM_{var_name}_SRC}}")\n' + inner + f'\n{indent}else()\n{indent}    set(ASM_{var_name}_OBJ "")\n{indent}    message(STATUS "[RAWRXD_SOURCE_AUTHORITY_001] OMIT absent optional MASM source: ${{ASM_{var_name}_SRC}}")\n{indent}endif()\n'
                # Replace in lines list
                lines = lines[:start_idx] + [wrapped + '\n'] + lines[end_idx+1:]
                changes += 1
                # Adjust index after replacement
                i = start_idx + 1
                continue
    i += 1

with open('F:/~dev/rawrxd/CMakeLists.txt', 'w', encoding='utf-8') as f:
    f.writelines(lines)

print(f'Patched {changes} ASM blocks')
