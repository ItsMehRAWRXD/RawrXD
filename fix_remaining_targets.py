#!/usr/bin/env python3
"""
fix_remaining_targets.py
Wrap remaining add_executable/add_library blocks that reference missing source files.
"""
import re, os, sys

cmake_path = r"F:\~dev\rawrxd\CMakeLists.txt"
backup_path = cmake_path + ".bak_remaining"

if not os.path.exists(backup_path):
    import shutil
    shutil.copy2(cmake_path, backup_path)

with open(cmake_path, "r", encoding="utf-8", errors="replace") as f:
    lines = f.readlines()

# List existing source files under rawrxd/src
existing_files = set()
src_base = r"F:\~dev\rawrxd\src"
for root, dirs, files in os.walk(src_base):
    for name in files:
        rel = os.path.relpath(os.path.join(root, name), r"F:\~dev\rawrxd").replace("\\", "/")
        existing_files.add(rel.lower())

# Also check for files at top-level src
for name in os.listdir(r"F:\~dev\rawrxd\src"):
    if os.path.isfile(os.path.join(r"F:\~dev\rawrxd\src", name)):
        existing_files.add(("src/" + name).replace("\\", "/").lower())

# Check specific directories that might exist elsewhere
def file_exists(rel_path):
    p = rel_path.replace("/", "\\")
    return os.path.exists(os.path.join(r"F:\~dev\rawrxd", p))

# Identify add_executable/add_library blocks that reference missing files
# We'll scan line by line and collect blocks.
# A block starts with add_executable or add_library and ends at the first
# unindented (or less indented) line that is not a continuation.
# For simplicity, we'll detect the pattern:
#   add_xxx(NAME
#       src/...)
# and check if any source file is missing.

# Actually easier: find lines that contain add_executable/add_library and then
# look for source files in the same block.
# We'll mark blocks where ANY source file referenced is missing.
# Then wrap the whole block with if(0)...endif()

# Pattern to match src/... references in a block
src_pattern = re.compile(r'(?:^|\s)(src/[A-Za-z0-9_/\-\+\.]+)')

# Let's build a list of block ranges.
blocks = []  # list of (start_line, end_line, has_missing)

i = 0
n = len(lines)
while i < n:
    line = lines[i]
    stripped = line.strip()
    if stripped.startswith("add_executable(") or stripped.startswith("add_library("):
        start = i
        # Determine the base indentation of this line
        base_indent = len(line) - len(line.lstrip())
        # Collect until we hit a line with indentation <= base_indent that is not empty/comment
        j = i + 1
        while j < n:
            next_line = lines[j]
            next_stripped = next_line.strip()
            if next_stripped == "" or next_stripped.startswith("#"):
                j += 1
                continue
            indent = len(next_line) - len(next_line.lstrip())
            if indent <= base_indent:
                break
            j += 1
        end = j  # exclusive
        # Check for missing files in this block
        has_missing = False
        for k in range(start, end):
            m = src_pattern.search(lines[k])
            if m:
                rel = m.group(1)
                if not file_exists(rel):
                    has_missing = True
                    #print(f"  Missing: {rel}")
                    break
        blocks.append((start, end, has_missing))
        i = end
    else:
        i += 1

print(f"Found {len(blocks)} add_executable/add_library blocks.")
missing_blocks = [b for b in blocks if b[2]]
print(f"Blocks with missing files: {len(missing_blocks)}")

# Now, for blocks with missing files, we need to wrap them in if(0) ... endif()
# But we must be careful: if the block is already inside if(0), skip it.
# Also check if there is already an if(0) just before the block.

edits = []
for start, end, has_missing in missing_blocks:
    if not has_missing:
        continue
    # Check if already wrapped
    # Look at lines[start-1], lines[start-2] etc for if(0)
    already_wrapped = False
    for k in range(start-1, max(start-5, -1), -1):
        if "if(0)" in lines[k] and "[RAWRXD_BUILD_AUTHORITY_BASELINE_001]" in lines[k]:
            already_wrapped = True
            break
        if lines[k].strip().startswith("if(") and "0)" in lines[k]:
            already_wrapped = True
            break
    if already_wrapped:
        continue
    # Also check if the block itself starts with if(0)
    block_text = "".join(lines[start:end])
    if "if(0)" in block_text:
        already_wrapped = True
        # But it might be a nested if(0) inside the block, not wrapping it.
        # We'll just skip if there's if(0) within 3 lines before.
        pass
    if already_wrapped:
        continue

    # Find a good insertion point: the line with the add_executable/add_library
    # We want to insert `if(0)` before start, and `endif()` after end.
    # But we need to account for the block possibly being inside an if() or option() block.
    # Actually, for simplicity, we'll wrap just the add_executable/add_library block.
    edits.append((start, end))
    print(f"Wrapping block lines {start+1}-{end}: lines[start]={lines[start].strip()[:60]}")

# Apply edits in reverse order so line numbers don't shift
edits.sort(key=lambda x: x[0], reverse=True)
for start, end in edits:
    # Determine indentation
    indent = len(lines[start]) - len(lines[start].lstrip())
    indent_str = lines[start][:indent]
    wrapped = [f"{indent_str}if(0)  # [RAWRXD_BUILD_AUTHORITY_BASELINE_001] Disabled: missing source files\n"]
    for k in range(start, end):
        # add extra indent to preserve structure? No, just keep as-is.
        wrapped.append(lines[k])
    wrapped.append(f"{indent_str}endif()\n")
    lines[start:end] = wrapped

with open(cmake_path, "w", encoding="utf-8", errors="replace") as f:
    f.writelines(lines)

print(f"Done. Written {len(lines)} lines to {cmake_path}")
