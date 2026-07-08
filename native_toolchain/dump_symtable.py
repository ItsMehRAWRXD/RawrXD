import struct

with open('test_exit.obj', 'rb') as f:
    data = f.read()

num_symbols = struct.unpack('<I', data[12:16])[0]
sym_table_offset = struct.unpack('<I', data[8:12])[0]
str_table_start = sym_table_offset + num_symbols * 18

print(f'Symbol table at: 0x{sym_table_offset:x}')
print(f'String table at: 0x{str_table_start:x}')
print()

for i in range(num_symbols):
    sym_off = sym_table_offset + i * 18

    # First 8 bytes: name
    name_bytes = data[sym_off:sym_off+8]

    # Check if long name
    if name_bytes[:4] == b'\x00\x00\x00\x00':
        str_offset = struct.unpack('<I', data[sym_off+4:sym_off+8])[0]
        name = data[str_table_start + str_offset:str_table_start + str_offset + 50].split(b'\x00')[0].decode('ascii', errors='ignore')
    else:
        name = name_bytes.rstrip(b'\x00').decode('ascii', errors='ignore')

    value = struct.unpack('<I', data[sym_off+8:sym_off+12])[0]
    section = struct.unpack('<h', data[sym_off+12:sym_off+14])[0]

    print(f'Symbol {i}: off=0x{sym_off:x}, name="{name}", value={value}, section={section}')
