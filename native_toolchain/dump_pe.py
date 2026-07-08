import struct

with open('test_exit2_v7.exe', 'rb') as f:
    msvc = f.read()

with open('test_exit_linked.exe', 'rb') as f:
    linked = f.read()

# PE offset is 0x40
pe_offset = 0x40
coff_offset = pe_offset + 4
opt_offset = coff_offset + 24

print('=== COFF Header ===')
print(f'  Machine: 0x{struct.unpack("<H", msvc[coff_offset:coff_offset+2])[0]:04x}')
print(f'  NumberOfSections: {struct.unpack("<H", msvc[coff_offset+2:coff_offset+4])[0]}')
print(f'  TimeDateStamp: {struct.unpack("<I", msvc[coff_offset+4:coff_offset+8])[0]}')
print(f'  PointerToSymbolTable: 0x{struct.unpack("<I", msvc[coff_offset+8:coff_offset+12])[0]:08x}')
print(f'  NumberOfSymbols: {struct.unpack("<I", msvc[coff_offset+12:coff_offset+16])[0]}')
print(f'  SizeOfOptionalHeader: {struct.unpack("<H", msvc[coff_offset+16:coff_offset+18])[0]}')
print(f'  Characteristics: 0x{struct.unpack("<H", msvc[coff_offset+18:coff_offset+20])[0]:04x}')

print()
print('=== Optional Header ===')
print(f'  Magic: 0x{struct.unpack("<H", msvc[opt_offset:opt_offset+2])[0]:04x}')
print(f'  MajorLinkerVersion: {msvc[opt_offset+2]}')
print(f'  MinorLinkerVersion: {msvc[opt_offset+3]}')
print(f'  SizeOfCode: 0x{struct.unpack("<I", msvc[opt_offset+4:opt_offset+8])[0]:08x}')
print(f'  SizeOfInitializedData: 0x{struct.unpack("<I", msvc[opt_offset+8:opt_offset+12])[0]:08x}')
print(f'  SizeOfUninitializedData: 0x{struct.unpack("<I", msvc[opt_offset+12:opt_offset+16])[0]:08x}')
print(f'  AddressOfEntryPoint: 0x{struct.unpack("<I", msvc[opt_offset+16:opt_offset+20])[0]:08x}')
print(f'  BaseOfCode: 0x{struct.unpack("<I", msvc[opt_offset+20:opt_offset+24])[0]:08x}')
print(f'  ImageBase: 0x{struct.unpack("<Q", msvc[opt_offset+24:opt_offset+32])[0]:016x}')
print(f'  SectionAlignment: 0x{struct.unpack("<I", msvc[opt_offset+32:opt_offset+36])[0]:08x}')
print(f'  FileAlignment: 0x{struct.unpack("<I", msvc[opt_offset+36:opt_offset+40])[0]:08x}')
print(f'  MajorOperatingSystemVersion: {struct.unpack("<H", msvc[opt_offset+40:opt_offset+42])[0]}')
print(f'  MinorOperatingSystemVersion: {struct.unpack("<H", msvc[opt_offset+42:opt_offset+44])[0]}')
print(f'  MajorImageVersion: {struct.unpack("<H", msvc[opt_offset+44:opt_offset+46])[0]}')
print(f'  MinorImageVersion: {struct.unpack("<H", msvc[opt_offset+46:opt_offset+48])[0]}')
print(f'  MajorSubsystemVersion: {struct.unpack("<H", msvc[opt_offset+48:opt_offset+50])[0]}')
print(f'  MinorSubsystemVersion: {struct.unpack("<H", msvc[opt_offset+50:opt_offset+52])[0]}')
print(f'  Win32VersionValue: 0x{struct.unpack("<I", msvc[opt_offset+52:opt_offset+56])[0]:08x}')
print(f'  SizeOfImage: 0x{struct.unpack("<I", msvc[opt_offset+56:opt_offset+60])[0]:08x}')
print(f'  SizeOfHeaders: 0x{struct.unpack("<I", msvc[opt_offset+60:opt_offset+64])[0]:08x}')
print(f'  CheckSum: 0x{struct.unpack("<I", msvc[opt_offset+64:opt_offset+68])[0]:08x}')
print(f'  Subsystem: {struct.unpack("<H", msvc[opt_offset+68:opt_offset+70])[0]}')
print(f'  DllCharacteristics: 0x{struct.unpack("<H", msvc[opt_offset+70:opt_offset+72])[0]:04x}')
print(f'  SizeOfStackReserve: 0x{struct.unpack("<Q", msvc[opt_offset+72:opt_offset+80])[0]:016x}')
print(f'  SizeOfStackCommit: 0x{struct.unpack("<Q", msvc[opt_offset+80:opt_offset+88])[0]:016x}')
print(f'  SizeOfHeapReserve: 0x{struct.unpack("<Q", msvc[opt_offset+88:opt_offset+96])[0]:016x}')
print(f'  SizeOfHeapCommit: 0x{struct.unpack("<Q", msvc[opt_offset+96:opt_offset+104])[0]:016x}')
print(f'  LoaderFlags: 0x{struct.unpack("<I", msvc[opt_offset+104:opt_offset+108])[0]:08x}')
print(f'  NumberOfRvaAndSizes: {struct.unpack("<I", msvc[opt_offset+108:opt_offset+112])[0]}')

print()
print('=== Data Directories ===')
for i in range(16):
    doff = opt_offset + 112 + i * 8
    rva = struct.unpack("<I", msvc[doff:doff+4])[0]
    size = struct.unpack("<I", msvc[doff+4:doff+8])[0]
    if rva != 0 or size != 0:
        print(f'  Directory {i}: RVA=0x{rva:08x}, Size={size}')

print()
print('=== Section Headers ===')
section_offset = opt_offset + 240
for i in range(2):
    soff = section_offset + i * 40
    name = msvc[soff:soff+8].rstrip(b'\x00').decode('ascii', errors='ignore')
    vsize = struct.unpack("<I", msvc[soff+8:soff+12])[0]
    vaddr = struct.unpack("<I", msvc[soff+12:soff+16])[0]
    rsize = struct.unpack("<I", msvc[soff+16:soff+20])[0]
    roff = struct.unpack("<I", msvc[soff+20:soff+24])[0]
    print(f'  Section {i} ({name}):')
    print(f'    VirtualSize: 0x{vsize:08x}')
    print(f'    VirtualAddress: 0x{vaddr:08x}')
    print(f'    SizeOfRawData: 0x{rsize:08x}')
    print(f'    PointerToRawData: 0x{roff:08x}')
