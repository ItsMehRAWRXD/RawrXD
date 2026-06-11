#!/usr/bin/env python3
"""
Extract WIN32IDE_SOURCES from CMakeLists.txt and generate ninja build rules.
"""
import re
import os

def extract_win32ide_sources(cmake_path):
    """Extract ALL WIN32IDE_SOURCES from CMakeLists.txt including list(APPEND ...) blocks."""
    with open(cmake_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    sources = set()
    
    # Pattern 1: set(WIN32IDE_SOURCES ...)
    # Pattern 2: list(APPEND WIN32IDE_SOURCES ...)
    
    # Find all blocks that add to WIN32IDE_SOURCES
    # We'll scan line by line for robustness
    lines = content.split('\n')
    
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        
        # Check if this line starts a WIN32IDE_SOURCES block
        is_set = stripped.startswith('set(WIN32IDE_SOURCES')
        is_append = stripped.startswith('list(APPEND WIN32IDE_SOURCES')
        
        if is_set or is_append:
            # Determine prefix length
            if is_set:
                prefix = 'set(WIN32IDE_SOURCES'
            else:
                prefix = 'list(APPEND WIN32IDE_SOURCES'
            
            # Collect all lines in this block
            block_lines = []
            
            # Check if the closing paren is on the same line
            remainder = stripped[len(prefix):]
            depth = remainder.count('(') - remainder.count(')')
            
            # If depth is already 0 or negative, the block ended on same line
            if depth <= 0 and ')' in remainder:
                # Single line block
                block_lines.append(remainder)
            else:
                # Multi-line block
                if depth <= 0:
                    depth = 1  # We entered with set( or list(APPEND
                
                i += 1
                while i < len(lines) and depth > 0:
                    block_line = lines[i]
                    block_lines.append(block_line)
                    
                    # Count parens, but ignore those in comments
                    # Simple approach: count all
                    depth += block_line.count('(') - block_line.count(')')
                    i += 1
                
                # Back up one since outer loop will increment
                i -= 1
            
            # Extract sources from block_lines
            for block_line in block_lines:
                block_line = block_line.strip()
                if not block_line or block_line.startswith('#'):
                    continue
                # Remove trailing comments
                if '#' in block_line:
                    block_line = block_line[:block_line.index('#')].strip()
                # Extract source paths
                for prefix in ('src/', 'Ship/'):
                    if prefix in block_line:
                        # Could be multiple paths on one line
                        parts = block_line.split()
                        for part in parts:
                            part = part.strip()
                            if part.startswith('src/') or part.startswith('Ship/'):
                                # Remove any trailing punctuation
                                part = part.rstrip(',)')
                                if part.endswith('.cpp') or part.endswith('.c') or part.endswith('.asm'):
                                    sources.add(part)
        
        i += 1
    
    return sorted(sources)

def generate_ninja_rules(sources, existing_ninja_path, output_ninja_path):
    """Generate ninja build rules for RawrXD-Win32IDE target."""
    
    # Read existing ninja file
    with open(existing_ninja_path, 'r', encoding='utf-8') as f:
        ninja_content = f.read()
    
    # Remove ALL existing RawrXD-Win32IDE compile rules and link rule
    # Pattern to match all RawrXD-Win32IDE build lines
    old_compile_pattern = r'build obj/RawrXD-Win32IDE/[^\n]+\.obj: compile [^\n]+\n(?:  includes = [^\n]+\n)?'
    ninja_content = re.sub(old_compile_pattern, '', ninja_content)
    
    # Remove old link rule for RawrXD-Win32IDE
    old_link_pattern = r'build bin/RawrXD-Win32IDE\.exe: link [^\n]+\n'
    ninja_content = re.sub(old_link_pattern, '', ninja_content)
    
    # Remove the "# RawrXD-Win32IDE target" comment if present
    ninja_content = re.sub(r'# RawrXD-Win32IDE target\n', '', ninja_content)
    
    # Generate complete RawrXD-Win32IDE section with directory-prefixed object names
    def make_obj_name(src):
        parts = src.split('/')
        if len(parts) >= 2:
            dir_part = parts[-2] if parts[-2] != 'src' else ''
            basename = os.path.splitext(parts[-1])[0]
            if dir_part:
                obj_name = f"{dir_part}_{basename}"
            else:
                obj_name = basename
        else:
            obj_name = os.path.splitext(parts[-1])[0]
        
        if src.startswith('Ship/'):
            obj_name = 'Ship_' + obj_name
        return obj_name
    
    win32ide_section = "# RawrXD-Win32IDE target\n"
    all_objs = []
    
    for src in sources:
        obj_name = make_obj_name(src)
        win32ide_section += f"build obj/RawrXD-Win32IDE/{obj_name}.obj: compile {src}\n"
        win32ide_section += f"  includes = /Iinclude /Isrc /Isrc/engine /Isrc/core /Isrc/server /Isrc/agent /Isrc/agentic /Isrc/cli /Isrc/win32app /Isrc/modules /Isrc/utils /Isrc/config /Isrc/asm /Isrc/lsp /Isrc/plugin_system /Isrc/ide /Isrc/llm_adapter /Isrc/auth /Isrc/context /Isrc/multimodal_engine /Isrc/telemetry /Isrc/ui /Isrc/git /I3rdparty/quickjs /I3rdparty/quickjs_ng /IShip\n"
        all_objs.append(f"obj/RawrXD-Win32IDE/{obj_name}.obj")
    
    win32ide_section += f"\nbuild bin/RawrXD-Win32IDE.exe: link {' '.join(all_objs)}\n"
    
    # Insert after the existing targets - find a good insertion point
    # Look for the end of existing targets (after bench_deflate_neon.exe)
    insert_marker = "build bin/bench_deflate_neon.exe: link \n\n"
    if insert_marker in ninja_content:
        ninja_content = ninja_content.replace(insert_marker, insert_marker + win32ide_section + "\n")
    else:
        # Append to end
        ninja_content += "\n" + win32ide_section
    
    with open(output_ninja_path, 'w', encoding='utf-8') as f:
        f.write(ninja_content)
    
    print(f"Wrote updated ninja file to {output_ninja_path}")
    print(f"Total objects in link: {len(all_objs)}")

if __name__ == '__main__':
    cmake_path = r'd:\rawrxd\CMakeLists.txt'
    ninja_path = r'd:\rawrxd\agentic_build\build.ninja'
    output_path = r'd:\rawrxd\agentic_build\build.ninja'
    
    sources = extract_win32ide_sources(cmake_path)
    # Filter out problematic files that have known compilation issues
    # with the QuickJS C API and C++ lambdas (JSValue macro conflicts)
    filtered_sources = [s for s in sources if s != 'src/core/js_extension_host.cpp']
    
    print(f"Filtered {len(sources) - len(filtered_sources)} problematic source(s)")
    sources = filtered_sources
    
    if sources:
        generate_ninja_rules(sources, ninja_path, output_path)
    else:
        print("No sources found!")
