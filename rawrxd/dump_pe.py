# dump_pe.py - minimal PE64 header dump
import sys, struct

path = sys.argv[1] if len(sys.argv) > 1 else 'hello.exe'
with open(path, 'rb') as f:
    data = f.read()

# DOS header
e_lfanew = struct.unpack('<I', data[0x3C:0x40])[0]
print(f'e_lfanew = 0x{e_lfanew:X}')

# COFF header
pe_sig = data[e_lfanew:e_lfanew+4]
print(f'PE signature = {pe_sig}')
coff = e_lfanew + 4
machine, numSections, timeStamp, ptrSymTab, numSyms, sizeOptHeader, characteristics = struct.unpack('<HHIIIHH', data[coff:coff+20])
print(f'  Machine=0x{machine:X} NumSections={numSections} SizeOfOptionalHeader={sizeOptHeader} Characteristics=0x{characteristics:X}')

# Optional header (PE32+)
opt = coff + 20
magic = struct.unpack('<H', data[opt:opt+2])[0]
print(f'  OptionalHeader Magic=0x{magic:X} (expected 0x20B)')

majorLinker = data[opt+2]
minorLinker = data[opt+3]
print(f'  MajorLinkerVer={majorLinker} MinorLinkerVer={minorLinker}')

sizeOfCode, sizeOfInitializedData, sizeOfUninitializedData, entryPoint, baseOfCode = struct.unpack('<IIIII', data[opt+4:opt+24])
print(f'  SizeOfCode=0x{sizeOfCode:X} SizeOfInitializedData=0x{sizeOfInitializedData:X} SizeOfUninitializedData=0x{sizeOfUninitializedData:X}')
print(f'  AddressOfEntryPoint=0x{entryPoint:X} BaseOfCode=0x{baseOfCode:X}')

imageBase = struct.unpack('<Q', data[opt+24:opt+32])[0]
print(f'  ImageBase=0x{imageBase:X}')

sectionAlignment, fileAlignment = struct.unpack('<II', data[opt+32:opt+40])
print(f'  SectionAlignment=0x{sectionAlignment:X} FileAlignment=0x{fileAlignment:X}')

majorOS, minorOS, majorImage, minorImage, majorSubsys, minorSubsys = struct.unpack('<HHHHHH', data[opt+40:opt+52])
print(f'  MajorOSVersion={majorOS} MinorOSVersion={minorOS} MajorImageVersion={majorImage} MinorImageVersion={minorImage} MajorSubsystemVersion={majorSubsys} MinorSubsystemVersion={minorSubsys}')

win32Version = struct.unpack('<I', data[opt+52:opt+56])[0]
print(f'  Win32VersionValue={win32Version}')

sizeOfImage, sizeOfHeaders, checksum, subsystem, dllCharacteristics = struct.unpack('<IIIIH', data[opt+56:opt+70])
print(f'  SizeOfImage=0x{sizeOfImage:X} SizeOfHeaders=0x{sizeOfHeaders:X} Checksum={checksum}')
print(f'  Subsystem={subsystem} (expected 3) DLLCharacteristics=0x{dllCharacteristics:X}')

sizeOfStackReserve, sizeOfStackCommit, sizeOfHeapReserve, sizeOfHeapCommit = struct.unpack('<QQQQ', data[opt+70:opt+102])
print(f'  SizeOfStackReserve=0x{sizeOfStackReserve:X} SizeOfStackCommit=0x{sizeOfStackCommit:X}')
print(f'  SizeOfHeapReserve=0x{sizeOfHeapReserve:X} SizeOfHeapCommit=0x{sizeOfHeapCommit:X}')

loaderFlags = struct.unpack('<I', data[opt+102:opt+106])[0]
numRvaAndSizes = struct.unpack('<I', data[opt+106:opt+110])[0]
print(f'  LoaderFlags={loaderFlags} NumberOfRvaAndSizes={numRvaAndSizes}')

dataDir = opt + 110
for i, name in enumerate(['EXPORT','IMPORT','RESOURCE','EXCEPTION','CERTIFICATE','BASE_RELOCATION','DEBUG','ARCHITECTURE','GLOBAL_PTR','TLS','LOAD_CONFIG','BOUND_IMPORT','IAT','DELAY_IMPORT','CLR_RUNTIME','RESERVED']):
    rva, size = struct.unpack('<II', data[dataDir + i*8 : dataDir + i*8 + 8])
    print(f'  DataDir[{i}] {name}: RVA=0x{rva:X} Size=0x{size:X}')

# Sections
sec = coff + 20 + sizeOptHeader
for i in range(numSections):
    name = data[sec+i*40:sec+i*40+8].rstrip(b'\x00').decode('ascii', errors='ignore')
    vsize, vaddr, rawSize, rawPtr, relocPtr, lineNums, numRelocs, numLines, flags = struct.unpack('<IIIIIIHHI', data[sec+i*40:sec+i*40+40])
    print(f'  Section[{i}] {name}: VSize=0x{vsize:X} VAddr=0x{vaddr:X} RawSize=0x{rawSize:X} RawPtr=0x{rawPtr:X} Flags=0x{flags:X}')
