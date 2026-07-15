import struct

with open('test_exit_linked.exe', 'rb') as f:
    data = f.read()

# .idata section at file offset 0x600, RVA 0x3000
idata_offset = 0x600
idata_rva = 0x3000

# IAT at RVA 0x3038 = file offset 0x638
iat_offset = idata_offset + (0x3038 - idata_rva)
print(f'IAT at file offset 0x{iat_offset:x}:')
for i in range(2):
    entry = struct.unpack('<Q', data[iat_offset + i*8:iat_offset + i*8 + 8])[0]
    print(f'  IAT[{i}]: 0x{entry:016x}')

# ILT at RVA 0x3028 = file offset 0x628
ilt_offset = idata_offset + (0x3028 - idata_rva)
print()
print(f'ILT at file offset 0x{ilt_offset:x}:')
for i in range(2):
    entry = struct.unpack('<Q', data[ilt_offset + i*8:ilt_offset + i*8 + 8])[0]
    print(f'  ILT[{i}]: 0x{entry:016x}')

# Name table at RVA 0x3048 = file offset 0x648
name_offset = idata_offset + (0x3048 - idata_rva)
print()
print(f'Name table at file offset 0x{name_offset:x}:')
hint = struct.unpack('<H', data[name_offset:name_offset+2])[0]
func_name = data[name_offset+2:name_offset+50].split(b'\x00')[0].decode('ascii', errors='ignore')
print(f'  Hint: {hint}, Name: \"{func_name}\"')

# DLL name at RVA 0x3056 = file offset 0x656
dll_name_offset = idata_offset + (0x3056 - idata_rva)
print()
print(f'DLL name at file offset 0x{dll_name_offset:x}:')
dll_name = data[dll_name_offset:dll_name_offset+50].split(b'\x00')[0].decode('ascii', errors='ignore')
print(f'  DLL: \"{dll_name}\"')
