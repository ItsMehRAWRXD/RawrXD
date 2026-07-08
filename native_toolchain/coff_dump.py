import struct

with open('test_exit.obj', 'rb') as f:
    data = f.read()

# Relocation at offset 0x98
relptr = 0x98
print('=== Relocation Entry ===')
vaddr = struct.unpack('<I', data[relptr:relptr+4])[0]
sym_idx = struct.unpack('<I', data[relptr+4:relptr+8])[0]
rel_type = struct.unpack('<H', data[relptr+8:relptr+10])[0]

print(f'Virtual Address: 0x{vaddr:08x}')
print(f'Symbol Index: {sym_idx}')
print(f'Type: 0x{rel_type:04x}')

# Symbol table is at 0x11a
# Each symbol is 18 bytes: Name (8) + Value (4) + Section (2) + Type (2) + StorageClass (1) + NumAux (1)
sym_offset = 0x11a + sym_idx * 18

# Check if it's a short name or long name
name_bytes = data[sym_offset:sym_offset+4]
if name_bytes[0:4] == b'\x00\x00\x00\x00':
    # Long name - offset in string table
    str_offset = struct.unpack('<I', data[sym_offset+4:sym_offset+8])[0]
    # String table starts after symbol table
    str_table_start = 0x11a + 10 * 18
    name = data[str_table_start + str_offset:str_table_start + str_offset + 50].split(b'\x00')[0].decode('ascii', errors='ignore')
else:
    name = data[sym_offset:sym_offset+8].rstrip(b'\x00').decode('ascii', errors='ignore')

print(f'Symbol Name: "{name}"')

# Raw code at offset 0x8c
print()
print('=== Raw .text$mn section (offset 0x8c) ===')
for i in range(0, 32, 16):
    hex_part = ' '.join(f'{b:02x}' for b in data[0x8c+i:0x8c+i+16])
    print(f'{0x8c+i:04x}: {hex_part}')

# Decode the instruction
print()
print('=== Instruction Decode ===')
code = data[0x8c:0x8c+12]
# First instruction: mov rcx, 42
# REX.W (48) + C7 /1 id (mov r/m64, imm32)
print(f'Bytes 0-6: {" ".join(f"{b:02x}" for b in code[0:7])}')
print(f'  -> mov rcx, {struct.unpack("<I", code[3:7])[0]}')

# Second instruction: call ExitProcess
# E8 cd (call rel32)
print(f'Bytes 7-10: {" ".join(f"{b:02x}" for b in code[7:11])}')
rel32 = struct.unpack("<i", code[8:12])[0]
print(f'  -> call rel32: {rel32} (0x{rel32:08x})')

# Third instruction: jmp [rip+offset]
# FF 25 disp32
print(f'Bytes 11+: {" ".join(f"{b:02x}" for b in code[11:17])}')
