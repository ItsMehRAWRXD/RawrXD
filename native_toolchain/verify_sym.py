import struct

with open('test_exit.obj', 'rb') as f:
    data = f.read()

sym_table_offset = struct.unpack('<I', data[8:12])[0]
num_symbols = struct.unpack('<I', data[12:16])[0]
str_table_start = sym_table_offset + num_symbols * 18

# Symbol 8 at offset 0x1aa
sym8_off = sym_table_offset + 8 * 18
print(f'Symbol 8 at file offset 0x{sym8_off:x}')

# Read as packed 18-byte structure
name = data[sym8_off:sym8_off+8]
value = struct.unpack('<I', data[sym8_off+8:sym8_off+12])[0]
section = struct.unpack('<h', data[sym8_off+12:sym8_off+14])[0]
sym_type = struct.unpack('<H', data[sym8_off+14:sym8_off+16])[0]
storage_class = data[sym8_off+16]
num_aux = data[sym8_off+17]

print(f'Name bytes: {name.hex()}')
print(f'First 4 bytes of name: {name[:4].hex()}')
print(f'Value: {value}')
print(f'Section: {section}')
print(f'Type: {sym_type}')
print(f'StorageClass: {storage_class}')
print(f'NumAux: {num_aux}')

if name[:4] == b'\x00\x00\x00\x00':
    str_offset = struct.unpack('<I', name[4:8])[0]
    print(f'String offset: {str_offset}')
    str_name = data[str_table_start + str_offset:str_table_start + str_offset + 50].split(b'\x00')[0]
    print(f'String: {str_name}')
else:
    print(f'Short name: {name.rstrip(b"\x00")}')
