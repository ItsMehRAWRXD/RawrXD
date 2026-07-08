import struct

with open('test_exit_linked.exe', 'rb') as f:
    data = f.read()

print(f'File size: {len(data)} bytes')

# .idata section at file offset 0x600, RVA 0x3000
idata_offset = 0x600
idata_rva = 0x3000

# Hint/name table at RVA 0x3058 = file offset 0x658
hint_offset = idata_offset + (0x3058 - idata_rva)
hint = struct.unpack('<H', data[hint_offset:hint_offset+2])[0]
func_name = data[hint_offset+2:hint_offset+50].split(b'\x00')[0].decode('ascii', errors='ignore')
print(f'Hint/Name at RVA 0x3058: Hint={hint}, Name="{func_name}"')

# Check the code at .text section (file offset 0x200)
text_offset = 0x200
print()
print('Code at file offset 0x200:')
for i in range(0, 16, 16):
    hex_part = ' '.join(f'{b:02x}' for b in data[text_offset+i:text_offset+i+16])
    print(f'  {text_offset+i:04x}: {hex_part}')

# Decode call instruction
call_offset = text_offset + 7
call_bytes = data[call_offset:call_offset+5]
print(f'Call bytes: {call_bytes.hex()}')
rel32 = struct.unpack('<i', call_bytes[1:5])[0]
print(f'Rel32: {rel32}')

# Calculate target
call_next_rva = 0x1000 + 7 + 5  # RVA of instruction after call
target_rva = call_next_rva + rel32
print(f'Target RVA: 0x{target_rva:08x}')
print(f'Expected IAT RVA: 0x3040')
print(f'Match: {target_rva == 0x3040}')
