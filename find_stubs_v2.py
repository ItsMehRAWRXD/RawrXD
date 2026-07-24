#!/usr/bin/env python3
"""Find all unlinked stub files in RawrXD project - Version 2"""

import os
import re
from pathlib import Path
from collections import defaultdict

PROJECT_ROOT = Path("d:/RawrXD")
CMAKE_FILE = PROJECT_ROOT / "CMakeLists.txt"

def extract_linked_files(cmake_content):
    """Extract all linked source files from CMakeLists.txt"""
    linked_files = set()
    
    # Pattern 1: Files in set(SOURCES ...) blocks
    # Match set(SOURCES ... ) blocks
    sources_blocks = re.findall(r'set\s*\(\s*SOURCES\s+([^)]+)\)', cmake_content, re.DOTALL)
    for block in sources_blocks:
        files = re.findall(r'src/[\w/\\_\-\.]+\.(?:cpp|c|h|hpp|asm)', block)
        for f in files:
            linked_files.add(f.replace('\\', '/').strip('/').lower())
    
    # Pattern 2: Files in target_sources
    target_blocks = re.findall(r'target_sources\s*\([^)]+\s+PRIVATE\s+([^)]+)\)', cmake_content, re.DOTALL)
    for block in target_blocks:
        files = re.findall(r'src/[\w/\\_\-\.]+\.(?:cpp|c|h|hpp|asm)', block)
        for f in files:
            linked_files.add(f.replace('\\', '/').strip('/').lower())
    
    # Pattern 3: Individual source file references (src/...)
    all_refs = re.findall(r'src/[\w/\\_\-\.]+\.(?:cpp|c|h|hpp|asm)', cmake_content)
    for ref in all_refs:
        linked_files.add(ref.replace('\\', '/').strip('/').lower())
    
    # Pattern 4: Files in add_executable
    exe_blocks = re.findall(r'add_executable\s*\([^)]+\s+([^)]+)\)', cmake_content, re.DOTALL)
    for block in exe_blocks:
        files = re.findall(r'src/[\w/\\_\-\.]+\.(?:cpp|c|h|hpp|asm)', block)
        for f in files:
            linked_files.add(f.replace('\\', '/').strip('/').lower())
    
    # Pattern 5: Variable references like ${SOURCES}
    var_pattern = r'\$\{(\w+)\}'
    vars_found = re.findall(var_pattern, cmake_content)
    
    return linked_files

def main():
    print("RawrXD Unlinked Stub Finder v2")
    print("=" * 70)
    
    # Read CMakeLists.txt
    cmake_content = CMAKE_FILE.read_text(encoding='utf-8', errors='ignore')
    
    # Extract linked files
    linked_files = extract_linked_files(cmake_content)
    
    print(f"\nFiles linked in CMakeLists.txt: {len(linked_files)}")
    
    # Key directories to scan
    source_dirs = [
        PROJECT_ROOT / "src",
        PROJECT_ROOT / "include", 
        PROJECT_ROOT / "agent",
        PROJECT_ROOT / "agentic",
        PROJECT_ROOT / "core",
        PROJECT_ROOT / "engine",
        PROJECT_ROOT / "inference",
        PROJECT_ROOT / "win32app",
        PROJECT_ROOT / "qtapp",
        PROJECT_ROOT / "asm",
        PROJECT_ROOT / "kernels",
        PROJECT_ROOT / "sovereign",
        PROJECT_ROOT / "tools",
        PROJECT_ROOT / "security",
        PROJECT_ROOT / "memory",
        PROJECT_ROOT / "websocket",
        PROJECT_ROOT / "server",
    ]
    
    # Collect all source files
    all_files = []
    extensions = {'.cpp', '.c', '.h', '.hpp', '.asm'}
    
    for src_dir in source_dirs:
        if src_dir.exists():
            for ext in extensions:
                all_files.extend(src_dir.rglob(f"*{ext}"))
    
    print(f"Source files found in directories: {len(all_files)}")
    
    # Find unlinked files
    unlinked = []
    for file_path in all_files:
        try:
            rel_path = str(file_path.relative_to(PROJECT_ROOT)).replace('\\', '/').lower()
            if rel_path not in linked_files:
                unlinked.append(file_path)
        except ValueError:
            pass
    
    # Group by directory
    by_dir = defaultdict(list)
    for f in unlinked:
        by_dir[f.parent].append(f.name)
    
    # Output results
    print("\n" + "=" * 70)
    print("UNLINKED STUB FILES")
    print("=" * 70)
    print(f"\nTotal unlinked: {len(unlinked)}\n")
    
    # Show first 100 files grouped by directory
    count = 0
    for dir_path, files in sorted(by_dir.items()):
        rel_dir = str(dir_path.relative_to(PROJECT_ROOT))
        print(f"\n[{rel_dir}]")
        for fname in sorted(files):
            print(f"  - {fname}")
            count += 1
            if count >= 100:
                print("\n  ... (truncated, see full report)")
                break
        if count >= 100:
            break
    
    # Save full report
    report_file = PROJECT_ROOT / "UNLINKED_STUBS_FULL.txt"
    with open(report_file, 'w') as f:
        f.write("RawrXD Unlinked Stub Files Report\n")
        f.write("=" * 70 + "\n")
        f.write(f"Total Unlinked: {len(unlinked)}\n\n")
        
        for dir_path, files in sorted(by_dir.items()):
            rel_dir = str(dir_path.relative_to(PROJECT_ROOT))
            f.write(f"\n[{rel_dir}]\n")
            for fname in sorted(files):
                f.write(f"  - {fname}\n")
    
    print(f"\n{'=' * 70}")
    print(f"Full report saved to: {report_file}")
    print(f"{'=' * 70}")
    
    # Summary by extension
    ext_counts = defaultdict(int)
    for f in unlinked:
        ext_counts[f.suffix.lower()] += 1
    
    print("\nSummary by extension:")
    for ext, count in sorted(ext_counts.items()):
        print(f"  {ext}: {count}")
    
    print(f"\nTotal linked in CMakeLists.txt: {len(linked_files)}")
    print(f"Total unlinked: {len(unlinked)}")

if __name__ == "__main__":
    main()
