import struct

with open('test_msvc.exe', 'rb') as f:
    data = f.read()

# .rdata section: RVA 0x2000, file offset 0x600
rdata_file_offset = 0x600
rdata_rva = 0x2000

# IAT is at RVA 0x2000, which is file offset 0x600
print('=== IAT at RVA 0x2000 (file offset 0x600) ===')
for i in range(8):
    entry = struct.unpack('<Q', data[0x600 + i*8:0x600 + i*8 + 8])[0]
    print(f'  IAT[{i}]: 0x{entry:016x}')

# Import directory is at RVA 0x2110, file offset 0x710
print()
print('=== Import Directory at file offset 0x710 ===')
for i in range(2):
    off = 0x710 + i*20
    orig_thunk = struct.unpack('<I', data[off:off+4])[0]
    timestamp = struct.unpack('<I', data[off+4:off+8])[0]
    forwarder = struct.unpack('<I', data[off+8:off+12])[0]
    name_rva = struct.unpack('<I', data[off+12:off+16])[0]
    first_thunk = struct.unpack('<I', data[off+16:off+20])[0]

    if orig_thunk == 0:
        print(f'  Entry {i}: NULL (end)')
        break

    # Get DLL name
    if name_rva >= rdata_rva:
        name_off = 0x600 + (name_rva - rdata_rva)
        dll_name = data[name_off:name_off+50].split(b'\x00')[0].decode('ascii', errors='ignore')
    else:
        dll_name = '???'

    print(f'  Entry {i}:')
    print(f'    OriginalFirstThunk: 0x{orig_thunk:08x}')
    print(f'    Name RVA: 0x{name_rva:08x} = "{dll_name}"')
    print(f'    FirstThunk (IAT RVA): 0x{first_thunk:08x}')

# Check the hint/name table at RVA 0x2148 (file offset 0x748)
print()
print('=== Import by name table at RVA 0x2148 ===')
hint_off = 0x600 + (0x2148 - 0x2000)
hint = struct.unpack('<H', data[hint_off:hint_off+2])[0]
func_name = data[hint_off+2:hint_off+50].split(b'\x00')[0].decode('ascii', errors='ignore')
print(f'  Hint: {hint}, Name: "{func_name}"')

# Check the DLL name at RVA 0x2156
print()
print('=== DLL name at RVA 0x2156 ===')
dll_off = 0x600 + (0x2156 - 0x2000)
dll_name = data[dll_off:dll_off+50].split(b'\x00')[0].decode('ascii', errors='ignore')
print(f'  DLL: "{dll_name}"')

# Now check the code at .text section
print()
print('=== .text section at RVA 0x1000 (file offset 0x400) ===')
for i in range(0, 32, 16):
    hex_part = ' '.join(f'{b:02x}' for b in data[0x400+i:0x400+i+16])
    print(f'  {0x400+i:04x}: {hex_part}')

# Decode the call instruction
print()
print('=== Call instruction decode ===')
# The call is at offset 7 in the code (after mov rcx, 42)
# File offset 0x407
# RVA 0x1007
call_bytes = data[0x407:0x40b]
print(f'Call bytes at file offset 0x407: {" ".join(f"{b:02x}" for b in call_bytes)}')
rel32 = struct.unpack('<i', call_bytes[1:5])[0]
print(f'Rel32 displacement: {rel32} (0x{rel32 & 0xffffffff:08x})')

# The target should be IAT entry at RVA 0x2000
# Call is at RVA 0x1007, next instruction at RVA 0x100b
call_next_rva = 0x100b
target_rva = call_next_rva + rel32
print(f'Call next instruction RVA: 0x{call_next_rva:08x}')
print(f'Target RVA: 0x{target_rva:08x}')
print(f'Expected IAT RVA: 0x2000')
print(f'Match: {target_rva == 0x2000}')
