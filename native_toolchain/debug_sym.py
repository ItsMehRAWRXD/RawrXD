import struct

with open('test_exit.obj', 'rb') as f:
    data = f.read()

sym_table_offset = struct.unpack('<I', data[8:12])[0]
num_symbols = struct.unpack('<I', data[12:16])[0]
str_table_start = sym_table_offset + num_symbols * 18

print(f'Symbol table at: 0x{sym_table_offset:x}')
print(f'Num symbols: {num_symbols}')
print(f'String table at: 0x{str_table_start:x}')

# Symbol 8 is at offset 0x1aa
sym8_off = sym_table_offset + 8 * 18
print(f'Symbol 8 file offset: 0x{sym8_off:x}')

# Read raw bytes
raw = data[sym8_off:sym8_off+18]
print(f'Raw bytes: {raw.hex()}')

# Parse manually
name = raw[0:8]
value = struct.unpack('<I', raw[8:12])[0]
section = struct.unpack('<h', raw[12:14])[0]
sym_type = struct.unpack('<H', raw[14:16])[0]
storage_class = raw[16]
num_aux = raw[17]

print(f'Name bytes: {name.hex()}')
print(f'Value: {value}')
print(f'Section: {section}')
print(f'Type: {sym_type}')
print(f'StorageClass: {storage_class}')
print(f'NumberOfAuxSymbols: {num_aux}')

# Check if long name
if name[:4] == b'\x00\x00\x00\x00':
    str_offset = struct.unpack('<I', name[4:8])[0]
    print(f'String offset: {str_offset}')
    str_name = data[str_table_start + str_offset:str_table_start + str_offset + 50].split(b'\x00')[0]
    print(f'String: "{str_name.decode(chr(97)+chr(115)+chr(99)+chr(105)+chr(105), errors=chr(105)+chr(103)+chr(110)+chr(111)+chr(114)+chr(101))}"')
else:
    print(f'Short name: "{name.rstrip(b"\x00").decode(chr(97)+chr(115)+chr(99)+chr(105)+chr(105), errors=chr(105)+chr(103)+chr(110)+chr(111)+chr(114)+chr(101))}"')
