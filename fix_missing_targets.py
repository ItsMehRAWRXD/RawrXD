import re, os

os.chdir(r'F:\~dev')

def get_block_end(lines, start_idx):
    """Find the end of a target definition block by tracking if/endif nesting."""
    depth = 0
    for j in range(start_idx, len(lines)):
        line = lines[j]
        # Count if/endif to track nesting
        if re.search(r'\bif\s*\(', line) and not line.strip().startswith('#'):
            depth += 1
        if re.search(r'\bendif\s*\(', line) and not line.strip().startswith('#'):
            depth -= 1
        
        if j > start_idx and depth <= 0:
            stripped = line.strip()
            # Block ends when we see a new top-level construct
            if (stripped.startswith('add_executable') or 
                stripped.startswith('add_library') or
                stripped.startswith('option(') or
                stripped.startswith('set(') or
                stripped.startswith('message(STATUS') or
                stripped.startswith('# ===') or
                stripped.startswith('# ==') or
                stripped.startswith('# ----------------------------------------------------------------') or
                stripped.startswith('# ═') or
                stripped.startswith('# ━') or
                stripped.startswith('# ') and ('==' in stripped or '━━' in stripped or '────' in stripped) or
                (stripped == '' and j+1 < len(lines) and 
                 (lines[j+1].strip().startswith('#') and any(c in lines[j+1] for c in '═━=')))):
                return j
    return len(lines)

def main():
    with open('rawrxd/CMakeLists.txt', 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # First pass: find all add_executable/add_library with missing sources
    to_wrap = []
    i = 0
    while i < len(lines):
        line = lines[i]
        match = re.match(r'^(\s*)(add_executable|add_library)\s*\(\s*(\w+)', line)
        if match:
            indent = match.group(1)
            target_name = match.group(3)
            
            # Collect all source files in this call (until closing paren)
            sources = []
            j = i
            paren_depth = line.count('(') - line.count(')')
            while j < len(lines) and paren_depth > 0:
                # Extract file paths from current line
                for m in re.finditer(r'[\w/]+\.(cpp|c|hpp|h|asm)', lines[j]):
                    sources.append(m.group(0))
                j += 1
                if j < len(lines):
                    paren_depth += lines[j].count('(') - lines[j].count(')')
            
            # Check if any source file is missing
            has_missing = False
            for src in sources:
                src_path = os.path.join('rawrxd', src.replace('/', os.sep))
                if not os.path.exists(src_path):
                    has_missing = True
                    print(f"Missing source for {target_name}: {src}")
                    break
            
            if has_missing:
                end_idx = get_block_end(lines, i)
                to_wrap.append((i, end_idx, target_name, indent))
        i += 1
    
    # Second pass: wrap blocks in reverse order (bottom to top)
    for start_idx, end_idx, target_name, indent in reversed(to_wrap):
        lines.insert(end_idx, f"{indent}endif()\n")
        lines.insert(start_idx, f"{indent}if(0)  # [RAWRXD_BUILD_AUTHORITY_BASELINE_001] Disabled: missing source files for {target_name}\n")
    
    with open('rawrxd/CMakeLists.txt', 'w', encoding='utf-8') as f:
        f.writelines(lines)
    
    print(f"Wrapped {len(to_wrap)} targets with missing sources")

if __name__ == '__main__':
    main()
