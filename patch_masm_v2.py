import re

with open('F:/~dev/rawrxd/CMakeLists.txt', 'r', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

i = 0
changes = 0
while i < len(lines):
    line = lines[i]
    m = re.match(r'^(\s*)set\(ASM_([A-Z0-9_]+)_SRC\s+"([^"]+\.asm)"\)', line)
    if m:
        indent = m.group(1)
        var_name = m.group(2)
        src_path = m.group(3)
        start_idx = i
        
        # Determine if this is a prebuilt block or simple block
        # Scan forward to classify the block
        j = i + 1
        is_prebuilt = False
        block_end = None
        
        while j < len(lines) and j < i + 50:  # safety limit
            l = lines[j]
            # Check for prebuilt markers
            if '_PREBUILT' in l and var_name in l:
                is_prebuilt = True
            
            # Find end of block
            # For simple blocks: add_custom_command closing )
            # For prebuilt blocks: the endif() that closes the if/elseif/else chain
            if is_prebuilt:
                if re.match(r'^\s*endif\(\)\s*$', l):
                    block_end = j
                    break
            else:
                if re.match(r'^\s*\)\s*$', l) and 'VERBATIM' in lines[j-1]:
                    block_end = j
                    break
            j += 1
        
        if block_end is not None:
            # Replace the block with set(ASM_VAR_OBJ "")
            replacement = f'{indent}set(ASM_{var_name}_OBJ "")\n'
            replacement += f'{indent}message(STATUS "[RAWRXD_SOURCE_AUTHORITY_001] OMIT absent optional MASM source: {src_path}")\n'
            
            lines = lines[:start_idx] + [replacement] + lines[block_end+1:]
            changes += 1
            i = start_idx + 1
            continue
    i += 1

with open('F:/~dev/rawrxd/CMakeLists.txt', 'w', encoding='utf-8') as f:
    f.writelines(lines)

print(f'Patched {changes} ASM blocks')
