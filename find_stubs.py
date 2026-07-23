#!/usr/bin/env python3
"""Find all unlinked stub files in RawrXD project"""

import os
import re
from pathlib import Path

PROJECT_ROOT = Path("d:/RawrXD")
CMAKE_FILE = PROJECT_ROOT / "CMakeLists.txt"

def main():
    print("RawrXD Unlinked Stub Finder")
    print("=" * 60)
    
    # Read CMakeLists.txt
    cmake_content = CMAKE_FILE.read_text(encoding='utf-8', errors='ignore')
    
    # Extract linked files
    linked_pattern = r'[\w/\\_\-\.]+\.(cpp|c|h|hpp|asm)'
    linked_matches = re.findall(linked_pattern, cmake_content)
    linked_files = set()
    for match in linked_matches:
        normalized = match.replace('\\', '/').strip('/')
        if normalized and not normalized.isdigit():
            linked_files.add(normalized.lower())
    
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
    
    print(f"Source files found: {len(all_files)}")
    
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
    from collections import defaultdict
    by_dir = defaultdict(list)
    for f in unlinked:
        by_dir[f.parent].append(f.name)
    
    # Output results
    print("\n" + "=" * 60)
    print("UNLINKED STUB FILES")
    print("=" * 60)
    print(f"\nTotal unlinked: {len(unlinked)}\n")
    
    # Show first 50 files grouped by directory
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
    report_file = PROJECT_ROOT / "UNLINKED_STUBS_REPORT.txt"
    with open(report_file, 'w') as f:
        f.write("RawrXD Unlinked Stub Files Report\n")
        f.write("=" * 60 + "\n")
        f.write(f"Generated: {os.path.basename(__file__)}\n")
        f.write(f"Total Unlinked: {len(unlinked)}\n\n")
        
        for dir_path, files in sorted(by_dir.items()):
            rel_dir = str(dir_path.relative_to(PROJECT_ROOT))
            f.write(f"\n[{rel_dir}]\n")
            for fname in sorted(files):
                f.write(f"  - {fname}\n")
    
    print(f"\n{'=' * 60}")
    print(f"Full report saved to: {report_file}")
    print(f"{'=' * 60}")
    
    # Summary by extension
    ext_counts = defaultdict(int)
    for f in unlinked:
        ext_counts[f.suffix] += 1
    
    print("\nSummary by extension:")
    for ext, count in sorted(ext_counts.items()):
        print(f"  {ext}: {count}")

if __name__ == "__main__":
    main()
