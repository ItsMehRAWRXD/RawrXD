import struct

with open('test_exit.obj', 'rb') as f:
    data = f.read()

sym_table_offset = struct.unpack('<I', data[8:12])[0]
num_symbols = struct.unpack('<I', data[12:16])[0]
str_table_start = sym_table_offset + num_symbols * 18

print(f'Symbol table at: 0x{sym_table_offset:x}')
print(f'Num symbols: {num_symbols}')
print(f'String table at: 0x{str_table_start:x}')

# Read string table size (first 4 bytes)
str_size = struct.unpack('<I', data[str_table_start:str_table_start+4])[0]
print(f'String table size field: {str_size}')

# Dump string table
print(f'String table contents: {data[str_table_start:str_table_start+20].hex()}')

# The actual strings start at offset 4 within the string table
print(f'String at offset 4: {data[str_table_start+4:str_table_start+20].split(b"\x00")[0]}')
