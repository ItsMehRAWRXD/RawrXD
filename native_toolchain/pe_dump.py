import struct

with open('test_msvc.exe', 'rb') as f:
    data = f.read(4096)

# .rdata section: RVA 0x2000, file offset 0x600
rdata_file_offset = 0x600
rdata_rva = 0x2000

print('=== IAT at RVA 0x2000 (file offset 0x600) ===')
iat_offset = rdata_file_offset
for i in range(4):
    entry = struct.unpack('<Q', data[iat_offset + i*8:iat_offset + i*8 + 8])[0]
    print(f'  IAT[{i}]: 0x{entry:016x}')

print()
print('=== Import Directory at RVA 0x2110 (file offset 0x710) ===')
import_dir_offset = rdata_file_offset + 0x110

for i in range(2):
    entry_off = import_dir_offset + i*32
    if entry_off + 32 > len(data):
        break

    orig_thunk = struct.unpack('<Q', data[entry_off:entry_off+8])[0]
    timestamp = struct.unpack('<I', data[entry_off+8:entry_off+12])[0]
    forwarder = struct.unpack('<I', data[entry_off+12:entry_off+16])[0]
    name_rva = struct.unpack('<Q', data[entry_off+16:entry_off+24])[0]
    first_thunk = struct.unpack('<Q', data[entry_off+24:entry_off+32])[0]

    if orig_thunk == 0 and name_rva == 0:
        print(f'  Entry {i}: NULL (end of import directory)')
        break

    # Get DLL name
    if name_rva >= rdata_rva and name_rva < rdata_rva + 512:
        name_file_off = rdata_file_offset + (name_rva - rdata_rva)
        dll_name = data[name_file_off:name_file_off+50].split(b'\x00')[0].decode('ascii', errors='ignore')
    else:
        dll_name = '???'

    print(f'  Entry {i}:')
    print(f'    OriginalFirstThunk: 0x{orig_thunk:016x}')
    print(f'    TimeDateStamp: {timestamp}')
    print(f'    ForwarderChain: {forwarder}')
    print(f'    Name RVA: 0x{name_rva:08x} = "{dll_name}"')
    print(f'    FirstThunk (IAT): 0x{first_thunk:016x}')

print()
print('=== Import Lookup Table (ILT) ===')
# OriginalFirstThunk points to ILT at RVA 0x2120 = file offset 0x720
ilt_offset = rdata_file_offset + 0x120
for i in range(4):
    entry = struct.unpack('<Q', data[ilt_offset + i*8:ilt_offset + i*8 + 8])[0]
    if entry == 0:
        print(f'  ILT[{i}]: 0x{entry:016x} (END)')
        break
    # Check if import by ordinal or by name
    if entry & 0x8000000000000000:
        ordinal = entry & 0xFFFF
        print(f'  ILT[{i}]: 0x{entry:016x} (Ordinal {ordinal})')
    else:
        # Import by name - entry is hint/name table RVA
        name_table_rva = entry
        if name_table_rva >= rdata_rva and name_table_rva < rdata_rva + 512:
            name_file_off = rdata_file_offset + (name_table_rva - rdata_rva)
            hint = struct.unpack('<H', data[name_file_off:name_file_off+2])[0]
            func_name = data[name_file_off+2:name_file_off+100].split(b'\x00')[0].decode('ascii', errors='ignore')
            print(f'  ILT[{i}]: 0x{entry:016x} (Hint {hint}, Name: "{func_name}")')
        else:
            print(f'  ILT[{i}]: 0x{entry:016x} (Name RVA out of range)')
