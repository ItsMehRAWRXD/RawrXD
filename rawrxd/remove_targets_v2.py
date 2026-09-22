import sys, re

filepath = sys.argv[1]
with open(filepath, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# The 12 blocks start at these exact header separator lines (1-based)
# Each block includes its header separator lines and runs until the next "# ===" separator
# or the next major section header like "# Certification Harness".
# The B013 block was already removed manually, but we'll handle it anyway.
start_pats = [
    (r'^# =+\n', "B013"),   # separator before B013
    (r'^# =+\n', "B014_COMPUTE"), # separator before B014 Compute
    (r'^# =+\n', "B014_BOUNDARY"),
    (r'^# =+\n', "B014_SINGLE"),
    (r'^# =+\n', "B014_LIFETIME"),
    (r'^# =+\n', "B005"),
    (r'^# =+\n', "B006"),
    (r'^# =+\n', "B007"),
    (r'^# =+\n', "B008"),
    (r'^# =+\n', "B010"),
    (r'^# =+\n', "B011"),
    (r'^# =+\n', "CERT"),
]

# Actually easier: use the comment titles that appear after the separator
block_titles = [
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

starts = []
for i, line in enumerate(lines):
    stripped = line.rstrip('\n')
    for title in block_titles:
        if stripped.startswith(title):
            # Also capture preceding separator line if present
            start_idx = i
            if i > 0 and lines[i-1].strip().startswith("# ="):
                start_idx = i - 1
            starts.append(start_idx)
            break

print(f"Found {len(starts)} blocks to remove")

# Determine end of each block: the line before the next block's start, or EOF.
starts = sorted(set(starts))
ends = []
for idx in range(len(starts)):
    if idx + 1 < len(starts):
        ends.append(starts[idx+1])
    else:
        ends.append(len(lines))

to_remove = set()
for s, e in zip(starts, ends):
    for i in range(s, e):
        to_remove.add(i)

print(f"Removing {len(to_remove)} lines")
new_lines = [lines[i] for i in range(len(lines)) if i not in to_remove]

with open(filepath, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)
print("Done")
