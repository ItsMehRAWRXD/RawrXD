import struct

with open('test_exit_linked.exe', 'rb') as f:
    data = f.read()

print(f'File size: {len(data)} bytes')
print()

# Check PE offset at offset 60
pe_offset = struct.unpack('<I', data[60:64])[0]
print(f'PE offset: 0x{pe_offset:x}')

# Check PE signature
pe_sig = struct.unpack('<I', data[pe_offset:pe_offset+4])[0]
print(f'PE signature: 0x{pe_sig:08x}')

# COFF header
coff_offset = pe_offset + 4
print()
print('COFF header:')
print(f'  Machine: 0x{struct.unpack("<H", data[coff_offset:coff_offset+2])[0]:04x}')
print(f'  NumberOfSections: {struct.unpack("<H", data[coff_offset+2:coff_offset+4])[0]}')
print(f'  SizeOfOptionalHeader: {struct.unpack("<H", data[coff_offset+16:coff_offset+18])[0]}')
print(f'  Characteristics: 0x{struct.unpack("<H", data[coff_offset+18:coff_offset+20])[0]:04x}')

# Optional header
opt_offset = coff_offset + 24
print()
print('Optional header:')
print(f'  Magic: 0x{struct.unpack("<H", data[opt_offset:opt_offset+2])[0]:04x}')
print(f'  AddressOfEntryPoint: 0x{struct.unpack("<I", data[opt_offset+16:opt_offset+20])[0]:08x}')
print(f'  ImageBase: 0x{struct.unpack("<Q", data[opt_offset+24:opt_offset+32])[0]:016x}')
print(f'  Subsystem: {struct.unpack("<H", data[opt_offset+68:opt_offset+70])[0]}')
print(f'  NumberOfRvaAndSizes: {struct.unpack("<I", data[opt_offset+108:opt_offset+112])[0]}')

# Section headers
section_offset = opt_offset + 240
print()
print('Section headers:')
for i in range(2):
    soff = section_offset + i * 40
    name = data[soff:soff+8].rstrip(b'\x00').decode('ascii', errors='ignore')
    print(f'  Section {i} ({name}):')
    print(f'    VirtualSize: 0x{struct.unpack("<I", data[soff+8:soff+12])[0]:08x}')
    print(f'    VirtualAddress: 0x{struct.unpack("<I", data[soff+12:soff+16])[0]:08x}')
    print(f'    SizeOfRawData: 0x{struct.unpack("<I", data[soff+16:soff+20])[0]:08x}')
    print(f'    PointerToRawData: 0x{struct.unpack("<I", data[soff+20:soff+24])[0]:08x}')
