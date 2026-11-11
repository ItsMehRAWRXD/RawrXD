import struct

with open('test_exit_linked.exe', 'rb') as f:
    data = f.read()

print('Hex dump of first 512 bytes:')
for i in range(0, min(512, len(data)), 16):
    hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
    print(f'{i:04x}: {hex_part:<48} {ascii_part}')
