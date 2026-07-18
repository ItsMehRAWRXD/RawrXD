# Read the file
with open('val016_repair_orchestrator.cpp', 'r') as f:
    lines = f.readlines()

# Find line 448 (0-indexed: 447)
print(f"Line 448 before: {repr(lines[447])}")

# The exact line content - let's just replace the specific parts
old_line = lines[447]

# Replace the problematic parts
# Change R"( to R"~~~(
# Change $))" to $)~~~"
if 'R"(' in old_line and '$))"' in old_line:
    new_line = old_line.replace('R"(', 'R"~~~(').replace('$))"', '$)~~~"')
    lines[447] = new_line
    print(f"Line 448 after: {repr(lines[447])}")
    print("Fixed!")
else:
    print("Pattern not found in expected format")
    # Try to find what we have
    if 'R"(' in old_line:
        print("Found R\"( in line")
    if '$))"' in old_line:
        print("Found $))\" in line")

# Write back
with open('val016_repair_orchestrator.cpp', 'w') as f:
    f.writelines(lines)

print("Done")
