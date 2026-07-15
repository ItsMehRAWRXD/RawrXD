import struct

with open('test_exit_linked.exe', 'rb') as f:
    data = f.read()

print('DOS header (first 64 bytes):')
print(f'  e_magic: 0x{struct.unpack("<H", data[0:2])[0]:04x}')
print(f'  e_lfanew: 0x{struct.unpack("<I", data[60:64])[0]:08x}')

pe_offset = struct.unpack('<I', data[60:64])[0]
print(f'PE signature at 0x{pe_offset:x}: 0x{struct.unpack("<I", data[pe_offset:pe_offset+4])[0]:08x}')

coff_offset = pe_offset + 4
print(f'COFF header at 0x{coff_offset:x}:')
print(f'  Machine: 0x{struct.unpack("<H", data[coff_offset:coff_offset+2])[0]:04x}')
print(f'  NumberOfSections: {struct.unpack("<H", data[coff_offset+2:coff_offset+4])[0]}')
print(f'  SizeOfOptionalHeader: {struct.unpack("<H", data[coff_offset+16:coff_offset+18])[0]}')

opt_offset = coff_offset + 20
print(f'Optional header at 0x{opt_offset:x}:')
print(f'  Magic: 0x{struct.unpack("<H", data[opt_offset:opt_offset+2])[0]:04x}')

# Calculate actual header size
# Find first section header
section_offset = opt_offset + struct.unpack('<H', data[coff_offset+16:coff_offset+18])[0]
print(f'Section headers start at: 0x{section_offset:x}')

# Get number of sections
num_sections = struct.unpack('<H', data[coff_offset+2:coff_offset+4])[0]
headers_end = section_offset + num_sections * 40
print(f'Headers end at: 0x{headers_end:x}')

# Check where code section starts
sect0_roff = struct.unpack('<I', data[section_offset+20:section_offset+24])[0]
print(f'Code section file offset: 0x{sect0_roff:x}')

# Check SizeOfHeaders
sizeof_headers = struct.unpack('<I', data[opt_offset+60:opt_offset+64])[0]
print(f'SizeOfHeaders: 0x{sizeof_headers:08x}')
