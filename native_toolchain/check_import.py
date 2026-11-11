import struct

with open('test_exit_linked.exe', 'rb') as f:
    data = f.read()

# Import section is at file offset 0x600
# idata_rva = 0x3000, text_rva = 0x1000
# So file offset = 0x600 + (0x3000 - 0x1000) = 0x2600? No wait...

# Actually:
# text_rva = 0x1000, text_file_offset = 0x200
# idata_rva = 0x3000
# So idata_file_offset = 0x200 + (0x3000 - 0x1000) = 0x2200

# But the hex dump showed import data at 0x600...
# Let me check the section header for .idata

pe_offset = struct.unpack('<I', data[60:64])[0]
coff_offset = pe_offset + 4
opt_offset = coff_offset + 20
section_offset = opt_offset + struct.unpack('<H', data[coff_offset+16:coff_offset+18])[0]

# Section 1 is .idata
idata_header_offset = section_offset + 40  # Skip first section header
idata_name = data[idata_header_offset:idata_header_offset+8].rstrip(b'\x00').decode('ascii', errors='ignore')
print(f'Section 1 name: {idata_name}')

idata_vsize = struct.unpack('<I', data[idata_header_offset+8:idata_header_offset+12])[0]
idata_vaddr = struct.unpack('<I', data[idata_header_offset+12:idata_header_offset+16])[0]
idata_rsize = struct.unpack('<I', data[idata_header_offset+16:idata_header_offset+20])[0]
idata_roff = struct.unpack('<I', data[idata_header_offset+20:idata_header_offset+24])[0]

print(f'  VirtualSize: 0x{idata_vsize:08x}')
print(f'  VirtualAddress: 0x{idata_vaddr:08x}')
print(f'  SizeOfRawData: 0x{idata_rsize:08x}')
print(f'  PointerToRawData: 0x{idata_roff:08x}')

# Now read the import directory at file offset idata_roff
print()
print('Import Directory Table:')
idt_offset = idata_roff
for i in range(2):
    import_lookup_rva = struct.unpack('<I', data[idt_offset+i*20:idt_offset+i*20+4])[0]
    time_date_stamp = struct.unpack('<I', data[idt_offset+i*20+4:idt_offset+i*20+8])[0]
    forwarder_chain = struct.unpack('<I', data[idt_offset+i*20+8:idt_offset+i*20+12])[0]
    name_rva = struct.unpack('<I', data[idt_offset+i*20+12:idt_offset+i*20+16])[0]
    iat_rva = struct.unpack('<I', data[idt_offset+i*20+16:idt_offset+i*20+20])[0]
    print(f'  Entry {i}:')
    print(f'    ImportLookupTableRVA: 0x{import_lookup_rva:08x}')
    print(f'    TimeDateStamp: {time_date_stamp}')
    print(f'    ForwarderChain: {forwarder_chain}')
    print(f'    NameRVA: 0x{name_rva:08x}')
    print(f'    ImportAddressTableRVA: 0x{iat_rva:08x}')

# Check IAT entries
print()
print('IAT entries (at file offset calculated from RVA):')
# IAT RVA = 0x3038
# idata_rva = 0x3000
# idata_file_offset = 0x600
# So IAT file offset = 0x600 + (0x3038 - 0x3000) = 0x638

iat_file_offset = idata_roff + (0x3038 - idata_vaddr)
print(f'IAT file offset: 0x{iat_file_offset:x}')

for i in range(2):
    entry = struct.unpack('<Q', data[iat_file_offset+i*8:iat_file_offset+i*8+8])[0]
    print(f'  IAT[{i}]: 0x{entry:016x}')
