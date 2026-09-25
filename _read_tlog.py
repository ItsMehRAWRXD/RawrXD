import struct, re
with open(r'F:\~dev\rawrxd\build\InferenceEngine.dir\Release\InferenceEngine.tlog\CL.command.1.tlog', 'rb') as f:
    data = f.read()
try:
    text = data.decode('utf-16-le')
except:
    text = data.decode('utf-8', errors='replace')
for i, line in enumerate(text.split('\r\n')):
    if 'Deep2Engine.cpp' in line and 'Gpu' not in line and 'Speculative' not in line and 'Vulkan' not in line and 'SsVk' not in line:
        print(f'Line {i}: {line[:500]}')
        print('---')
