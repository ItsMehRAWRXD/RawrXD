import struct

with open('test_exit.obj', 'rb') as f:
    data = f.read()

num_symbols = struct.unpack('<I', data[12:16])[0]
sym_table_offset = struct.unpack('<I', data[8:12])[0]
str_table_start = sym_table_offset + num_symbols * 18

# Read string table size
str_table_size = struct.unpack('<I', data[str_table_start:str_table_start+4])[0]
print(f'String table size: {str_table_size}')
print(f'String table starts at: 0x{str_table_start:x}')

# Dump string table
print()
print('=== String Table ===')
offset = 4
while offset < str_table_size:
    s = data[str_table_start + offset:str_table_start + offset + 50].split(b'\x00')[0]
    if s:
        print(f'  Offset {offset}: "{s.decode(chr(97)+chr(115)+chr(99)+chr(105)+chr(105), errors=chr(105)+chr(103)+chr(110)+chr(111)+chr(114)+chr(101))}"')
    offset += len(s) + 1
    if offset > 100:
        break
