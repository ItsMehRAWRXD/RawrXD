#!/usr/bin/env python3
"""
Remove all Qt references from CMakeLists.txt.
This script removes:
1. find_package(Qt6 ...) calls
2. if(Qt6_FOUND) blocks and their contents
3. if(Qt6Widgets_FOUND) blocks and their contents
4. if(MSVC AND RAWRXD_BUILD_WIN32IDE_QT AND Qt6_FOUND) blocks and their contents
5. if(Qt6WebSockets_FOUND) blocks and their contents

The script tracks if/endif nesting to correctly remove only the Qt blocks.
"""

import re
import sys

def remove_qt_blocks(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        
        # Check for Qt-related if blocks
        if re.match(r'if\s*\(\s*Qt6_FOUND', stripped):
            # Found a Qt6_FOUND block - skip until matching endif
            # Track nesting level
            nesting = 1
            i += 1
            while i < len(lines) and nesting > 0:
                current = lines[i].strip()
                # Count if/endif in this line
                if_count = len(re.findall(r'\bif\s*\(', current))
                endif_count = len(re.findall(r'\bendif\s*\(', current))
                nesting += if_count - endif_count
                i += 1
            # Skip the Qt block (don't add to result)
            continue
        
        if re.match(r'if\s*\(\s*Qt6Widgets_FOUND', stripped):
            # Found a Qt6Widgets_FOUND block - skip until matching endif
            nesting = 1
            i += 1
            while i < len(lines) and nesting > 0:
                current = lines[i].strip()
                if_count = len(re.findall(r'\bif\s*\(', current))
                endif_count = len(re.findall(r'\bendif\s*\(', current))
                nesting += if_count - endif_count
                i += 1
            continue
        
        if re.match(r'if\s*\(\s*Qt6WebSockets_FOUND', stripped):
            # Found a Qt6WebSockets_FOUND block - skip until matching endif
            nesting = 1
            i += 1
            while i < len(lines) and nesting > 0:
                current = lines[i].strip()
                if_count = len(re.findall(r'\bif\s*\(', current))
                endif_count = len(re.findall(r'\bendif\s*\(', current))
                nesting += if_count - endif_count
                i += 1
            continue
        
        if re.match(r'if\s*\(\s*MSVC\s+AND\s+RAWRXD_BUILD_WIN32IDE_QT\s+AND\s+Qt6_FOUND', stripped):
            # Found the Win32IDE Qt block - skip until matching endif
            nesting = 1
            i += 1
            while i < len(lines) and nesting > 0:
                current = lines[i].strip()
                if_count = len(re.findall(r'\bif\s*\(', current))
                endif_count = len(re.findall(r'\bendif\s*\(', current))
                nesting += if_count - endif_count
                i += 1
            continue
        
        # Check for find_package(Qt6 ...) calls
        if re.match(r'find_package\s*\(\s*Qt6', stripped):
            # Skip this line
            i += 1
            continue
        
        # Normal line - add to result
        result.append(line)
        i += 1
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.writelines(result)
    
    print(f"Removed Qt blocks. Original lines: {len(lines)}, New lines: {len(result)}")

if __name__ == '__main__':
    remove_qt_blocks(sys.argv[1])