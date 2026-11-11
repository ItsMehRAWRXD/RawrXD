import struct

with open('test_exit_linked.exe', 'rb') as f:
    data = f.read()

# Check optional header magic at different offsets
for offset in [0x54, 0x56, 0x58, 0x5a]:
    magic = struct.unpack('<H', data[offset:offset+2])[0]
    print(f'Optional header magic at 0x{offset:x}: 0x{magic:04x}')

# Check section header name at different offsets
for offset in [0x138, 0x140, 0x148]:
    name = data[offset:offset+8].rstrip(b'\x00').decode('ascii', errors='ignore')
    print(f'Section name at 0x{offset:x}: "{name}"')
