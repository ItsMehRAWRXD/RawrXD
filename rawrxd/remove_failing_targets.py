import sys

filepath = sys.argv[1]
with open(filepath, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# We will remove blocks from the line containing the start pattern to the line just before the next block.
# Each block ends with a line that is followed by a blank line and then a new comment block.
# For certification_harness, the block ends after a message(STATUS ...) line which is before a blank line and a new section.

remove_start_patterns = [
    "# ============================================================================\n",
    "# B013:",
    "# B014: Compute Decomposition Measurement",
    "# B014-BoundaryProbe:",
    "# B014-SingleBoundary:",
    "# B014-LifetimeProbe:",
    "# B005: Canonical Model Certification",
    "# B006: KV Cache Verification",
    "# B007: Performance Baseline Certification",
    "# B008: Build / CI Integration Gate",
    "# B010: Weight Residency Profiling Baseline (FROZEN)",
    "# B011: Targeted Weight Residency Optimization",
    "# Certification Harness",
]

# Find all start indices
starts = []
for i, line in enumerate(lines):
    for pat in remove_start_patterns:
        if pat in line:
            starts.append(i)
            break

starts = sorted(set(starts))
print(f"Found {len(starts)} start markers")

# Determine end indices: for each start, find the next start that is preceded by a blank line and a comment block start, or a specific end pattern.
# Actually, the file is structured with comment blocks starting with "# ===..." followed by a comment line.
# The blocks we want to remove start at their comment header and end just before the next block's "# ===..." header.
# But some blocks start with "# ============================================================================" which is the separator before the actual comment.
# Let's look at the structure: there are separator lines "# ===..." followed by a comment line like "# B013: ...". Then the block content. Then before the next block there's another "# ===..." line.
# Actually, looking at the file: after an endif() block there is a blank line, then "# ===..." separator, then the next block title.
# But B013 starts with a "# ===..." line at line 15237, then "# B013: ..." at line 15239.
# B014 starts with "# ===..." at line 15287, then "# B014: ..." at line 15289.
# So each block includes its preceding "# ===..." separator.

# Wait, the first block before B013 is the endif() for BUILD_TESTING for B004. Then a blank line, then "# ===...", then "# B013: ...".
# So to remove B013, we should remove from "# ===..." line to just before the next "# ===..." line.
# But B013 block ends with an endif() and a blank line before the next "# ===...".

# Let me use a simpler approach: just comment out the add_executable lines and set() lines for each target.
# CMake will still parse the set() and add_executable() but if the source lists are empty or missing files, it will still fail.
# Actually, if we comment out the add_executable line and the set line, the variable won't be defined, but the add_executable line is commented out so no target is created.
# However, there are also rawrxd_configure_b004_target(), target_compile_definitions(), target_compile_options(), target_include_directories(), target_link_libraries(), add_test() etc.
# If we only comment out add_executable, the other target_* commands will fail because the target doesn't exist.
# So we need to remove the entire block for each target.

# Let's use a line-range removal based on known line numbers from grep_search.
# We know the start line numbers from grep_search results:
# B013: line 15237 (the "# ===" separator before "# B013:")
# B014 Compute: line 15285
# B014 BoundaryProbe: line 15333
# B014 SingleBoundary: line 15381
# B014 LifetimeProbe: line 15429
# B005: line 15477
# B006: line 15501
# B007: line 15581
# B008: line 15663
# B010: line 15689
# B011: line 15766
# Certification Harness: line 16457

# The end of each block is the line just before the next block's "# ===" separator.
# But we don't know the exact end line numbers yet.
# Let's find them by scanning for the next "# ===" or "# Certification Harness" after each start.

start_lines = [
    (15237, "B013"),
    (15285, "B014_COMPUTE"),
    (15333, "B014_BOUNDARY"),
    (15381, "B014_SINGLE"),
    (15429, "B014_LIFETIME"),
    (15477, "B005"),
    (15501, "B006"),
    (15581, "B007"),
    (15663, "B008"),
    (15689, "B010"),
    (15766, "B011"),
    (16457, "CERT"),
]

# Adjust to 0-based indexing
start_indices = [sl - 1 for sl, _ in start_lines]

# For each start, find the next line that starts with "# ===" (separator) and is followed by a non-empty comment line,
# OR a line that starts with "# B" or "# Certification Harness" (next block).
# Actually simpler: the next block starts with a line like "# ===..." or "# B0XX:" or "# Certification Harness".
# Let's find for each start the next line that matches r'^# (={10,}|Certification Harness)'.

import re
next_sep_pattern = re.compile(r'^# (={10,}|Certification Harness)')

ends = []
for idx in start_indices:
    end_idx = None
    for j in range(idx + 1, len(lines)):
        if next_sep_pattern.match(lines[j]):
            end_idx = j
            break
    if end_idx is None:
        end_idx = len(lines)
    ends.append(end_idx)

# Remove from start to end-1 (inclusive)
# But we want to keep the "# ===" separator of the next block, so we remove up to end_idx - 1.
# Actually the next block's separator is part of the next block, so we should not include it.
# end_idx is the line number of the next separator. We want to remove lines [start_idx, end_idx) i.e., up to but not including end_idx.

to_remove = []
for s, e in zip(start_indices, ends):
    to_remove.extend(range(s, e))

to_remove = sorted(set(to_remove))
print(f"Removing {len(to_remove)} lines")

new_lines = [lines[i] for i in range(len(lines)) if i not in to_remove]

with open(filepath, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print("Done")
