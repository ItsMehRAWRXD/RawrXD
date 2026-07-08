import struct

with open('test_exit.obj', 'rb') as f:
    data = f.read()

# Relocation at offset 0x98
relptr = 0x98
vaddr = struct.unpack('<I', data[relptr:relptr+4])[0]
sym_idx = struct.unpack('<I', data[relptr+4:relptr+8])[0]
rel_type = struct.unpack('<H', data[relptr+8:relptr+10])[0]

print(f'Relocation at file offset 0x98:')
print(f'  Virtual Address: 0x{vaddr:08x}')
print(f'  Symbol Index: {sym_idx}')
print(f'  Type: 0x{rel_type:04x}')

# Check if symbol index 8 is ExitProcess
num_symbols = struct.unpack('<I', data[12:16])[0]
sym_table_offset = struct.unpack('<I', data[8:12])[0]
str_table_start = sym_table_offset + num_symbols * 18

sym_offset = sym_table_offset + sym_idx * 18
first4 = data[sym_offset:sym_offset+4]
if first4 == b'\x00\x00\x00\x00':
    str_offset = struct.unpack('<I', data[sym_offset+4:sym_offset+8])[0]
    name = data[str_table_start + str_offset:str_table_start + str_offset + 50].split(b'\x00')[0].decode('ascii', errors='ignore')
else:
    name = data[sym_offset:sym_offset+8].rstrip(b'\x00').decode('ascii', errors='ignore')

print(f'  Symbol {sym_idx} name: "{name}"')

# Check the code at that offset
print()
print(f'Code at offset {vaddr}:')
code_off = 0x8c + vaddr
print(f'  File offset 0x{code_off:x}: {data[code_off:code_off+4].hex()}')
