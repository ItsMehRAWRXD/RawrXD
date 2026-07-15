import struct

with open('test_exit_linked.exe', 'rb') as f:
    data = f.read()

# Code section is at file offset 0x200
# Check the code bytes
print('Code at 0x200:')
code = data[0x200:0x210]
print(' '.join(f'{b:02x}' for b in code))

# Disassemble:
# 48 c7 c1 2a 00 00 00 = mov rcx, 42
# e8 2c 20 00 00 = call rel32 (offset 0x202c)

# The call is at offset 7 in the code, with 5 bytes: e8 2c 20 00 00
# rel32 = 0x202c
# Target = 0x1000 (text RVA) + 7 + 5 + 0x202c = 0x3038

# Let's verify the relocation was applied
rel32 = struct.unpack('<I', data[0x200+7+1:0x200+7+5])[0]
print(f'rel32 value: 0x{rel32:08x} ({rel32})')

# If the relocation was applied correctly:
# text_rva = 0x1000
# call_offset = 7
# instruction_size = 5
# target = text_rva + call_offset + instruction_size + rel32
# 0x3038 = 0x1000 + 7 + 5 + rel32
# rel32 = 0x3038 - 0x1000 - 7 - 5 = 0x202c

text_rva = 0x1000
call_offset = 7
instruction_size = 5
target = text_rva + call_offset + instruction_size + rel32
print(f'Target RVA: 0x{target:08x}')

# IAT should be at 0x3038
print(f'Expected IAT at: 0x3038')
print(f'Match: {target == 0x3038}')
