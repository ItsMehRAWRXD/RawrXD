import struct

with open('test_exit_linked.exe', 'rb') as f:
    data = f.read()

print('Hex dump of 0x200-0x400 (code section):')
for i in range(0x200, min(0x400, len(data)), 16):
    hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
    print(f'{i:04x}: {hex_part:<48} {ascii_part}')

print()
print('Hex dump of 0x600-0x800 (import section):')
for i in range(0x600, min(0x800, len(data)), 16):
    hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
    print(f'{i:04x}: {hex_part:<48} {ascii_part}')
