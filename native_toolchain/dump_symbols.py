import struct

with open('test_exit.obj', 'rb') as f:
    data = f.read()

# COFF header
coff_offset = 0
num_sections = struct.unpack('<H', data[2:4])[0]
num_symbols = struct.unpack('<I', data[12:16])[0]
sym_table_offset = struct.unpack('<I', data[8:12])[0]

print(f'Number of symbols: {num_symbols}')
print(f'Symbol table offset: 0x{sym_table_offset:x}')

# Read all symbols
print()
print('=== Symbol Table ===')
for i in range(num_symbols):
    sym_off = sym_table_offset + i * 18

    # Check name
    name_bytes = data[sym_off:sym_off+4]
    if name_bytes == b'\x00\x00\x00\x00':
        # Long name
        str_offset = struct.unpack('<I', data[sym_off+4:sym_off+8])[0]
        str_table_start = sym_table_offset + num_symbols * 18
        name = data[str_table_start + str_offset:str_table_start + str_offset + 100].split(b'\x00')[0].decode('ascii', errors='ignore')
    else:
        name = data[sym_off:sym_off+8].rstrip(b'\x00').decode('ascii', errors='ignore')

    value = struct.unpack('<I', data[sym_off+8:sym_off+12])[0]
    section = struct.unpack('<h', data[sym_off+12:sym_off+14])[0]
    storage_class = data[sym_off+16]

    print(f'  Symbol {i}: "{name}" value={value} section={section} class={storage_class}')
