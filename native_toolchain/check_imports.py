import struct

with open('test_exit_linked.exe', 'rb') as f:
    data = f.read()

# .idata section at file offset 0x600, RVA 0x3000
idata_offset = 0x600
idata_rva = 0x3000

print('Import directory at file offset 0x600:')
for i in range(2):
    off = idata_offset + i*20
    orig_thunk = struct.unpack('<I', data[off:off+4])[0]
    timestamp = struct.unpack('<I', data[off+4:off+8])[0]
    forwarder = struct.unpack('<I', data[off+8:off+12])[0]
    name_rva = struct.unpack('<I', data[off+12:off+16])[0]
    first_thunk = struct.unpack('<I', data[off+16:off+20])[0]

    if orig_thunk == 0:
        print(f'  Entry {i}: NULL (end)')
        break

    # Get DLL name
    if name_rva >= idata_rva:
        name_off = idata_offset + (name_rva - idata_rva)
        dll_name = data[name_off:name_off+50].split(b'\x00')[0].decode('ascii', errors='ignore')
    else:
        dll_name = '???'

    print(f'  Entry {i}:')
    print(f'    OriginalFirstThunk: 0x{orig_thunk:08x}')
    print(f'    TimeDateStamp: {timestamp}')
    print(f'    ForwarderChain: {forwarder}')
    print(f'    Name RVA: 0x{name_rva:08x} = "{dll_name}"')
    print(f'    FirstThunk (IAT RVA): 0x{first_thunk:08x}')

# Check IAT at RVA 0x3038 = file offset 0x638
iat_offset = idata_offset + (0x3038 - idata_rva)
print()
print(f'IAT at file offset 0x{iat_offset:x}:')
for i in range(2):
    entry = struct.unpack('<Q', data[iat_offset + i*8:iat_offset + i*8 + 8])[0]
    print(f'  IAT[{i}]: 0x{entry:016x}')
