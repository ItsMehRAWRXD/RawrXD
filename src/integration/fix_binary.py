# Read the file in binary mode
with open('val016_repair_orchestrator.cpp', 'rb') as f:
    content = f.read()

# The exact bytes we're looking for
# R"((.+?)\((\d+)(?:,(\d+))?\)\s*:\s*(error|warning)\s+([A-Z]\d+)\s*:\s*(.+?)$))");
old_bytes = b'std::regex errorPattern(R"((.+?)\\((\\d+)(?:,(\\d+))?\\)\\s*:\\s*(error|warning)\\s+([A-Z]\\d+)\\s*:\\s*(.+?)$))");'

# New version with ~~~ delimiter
new_bytes = b'std::regex errorPattern(R"~~~((.+?)\\((\\d+)(?:,(\\d+))?\\)\\s*:\\s*(error|warning)\\s+([A-Z]\\d+)\\s*:\\s*(.+?)$)~~~");'

print(f"Looking for {len(old_bytes)} bytes")
print(f"Old bytes: {old_bytes[:50]}...")

if old_bytes in content:
    content = content.replace(old_bytes, new_bytes)
    with open('val016_repair_orchestrator.cpp', 'wb') as f:
        f.write(content)
    print("Fixed!")
else:
    print("Pattern not found")
    # Let's find what we actually have
    idx = content.find(b'std::regex errorPattern')
    if idx >= 0:
        print(f"Found at index {idx}: {content[idx:idx+150]}")
