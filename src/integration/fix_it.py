with open('val016_repair_orchestrator.cpp', 'rb') as f:
    data = f.read()

# Find the line
idx = data.find(b'std::regex errorPattern(R"((.+?)')
if idx >= 0:
    print(f'Found at position {idx}')
    # Show surrounding bytes
    print(f'Context: {data[idx:idx+200]}')
else:
    print('Not found')
