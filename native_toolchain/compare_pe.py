import struct

# Compare with test_msvc.exe
with open('test_msvc.exe', 'rb') as f:
    msvc_data = f.read()

with open('test_exit_linked.exe', 'rb') as f:
    linked_data = f.read()

print('Comparing PE structures:')
print()

# DOS header
print('DOS header:')
print(f'  test_msvc.exe: magic=0x{struct.unpack("<H", msvc_data[0:2])[0]:04x}, pe_offset=0x{struct.unpack("<I", msvc_data[60:64])[0]:x}')
print(f'  test_exit_linked.exe: magic=0x{struct.unpack("<H", linked_data[0:2])[0]:04x}, pe_offset=0x{struct.unpack("<I", linked_data[60:64])[0]:x}')

# PE signature
msvc_pe = struct.unpack('<I', msvc_data[0x40:0x44])[0]
linked_pe = struct.unpack('<I', linked_data[0x40:0x44])[0]
print(f'PE signature:')
print(f'  test_msvc.exe: 0x{msvc_pe:08x}')
print(f'  test_exit_linked.exe: 0x{linked_pe:08x}')

# COFF header
msvc_coff = 0x44
linked_coff = 0x44

msvc_machine = struct.unpack('<H', msvc_data[msvc_coff:msvc_coff+2])[0]
linked_machine = struct.unpack('<H', linked_data[linked_coff:linked_coff+2])[0]
print(f'Machine:')
print(f'  test_msvc.exe: 0x{msvc_machine:04x}')
print(f'  test_exit_linked.exe: 0x{linked_machine:04x}')

msvc_num_sections = struct.unpack('<H', msvc_data[msvc_coff+2:msvc_coff+4])[0]
linked_num_sections = struct.unpack('<H', linked_data[linked_coff+2:linked_coff+4])[0]
print(f'Number of sections:')
print(f'  test_msvc.exe: {msvc_num_sections}')
print(f'  test_exit_linked.exe: {linked_num_sections}')

msvc_opt_size = struct.unpack('<H', msvc_data[msvc_coff+16:msvc_coff+18])[0]
linked_opt_size = struct.unpack('<H', linked_data[linked_coff+16:linked_coff+18])[0]
print(f'SizeOfOptionalHeader:')
print(f'  test_msvc.exe: {msvc_opt_size}')
print(f'  test_exit_linked.exe: {linked_opt_size}')

# Optional header
msvc_opt = msvc_coff + 24
linked_opt = linked_coff + 24

msvc_magic = struct.unpack('<H', msvc_data[msvc_opt:msvc_opt+2])[0]
linked_magic = struct.unpack('<H', linked_data[linked_opt:linked_opt+2])[0]
print(f'Optional header magic:')
print(f'  test_msvc.exe: 0x{msvc_magic:04x}')
print(f'  test_exit_linked.exe: 0x{linked_magic:04x}')

msvc_entry = struct.unpack('<I', msvc_data[msvc_opt+16:msvc_opt+20])[0]
linked_entry = struct.unpack('<I', linked_data[linked_opt+16:linked_opt+20])[0]
print(f'Entry point:')
print(f'  test_msvc.exe: 0x{msvc_entry:08x}')
print(f'  test_exit_linked.exe: 0x{linked_entry:08x}')

msvc_image_base = struct.unpack('<Q', msvc_data[msvc_opt+24:msvc_opt+32])[0]
linked_image_base = struct.unpack('<Q', linked_data[linked_opt+24:linked_opt+32])[0]
print(f'Image base:')
print(f'  test_msvc.exe: 0x{msvc_image_base:016x}')
print(f'  test_exit_linked.exe: 0x{linked_image_base:016x}')

msvc_subsystem = struct.unpack('<H', msvc_data[msvc_opt+68:msvc_opt+70])[0]
linked_subsystem = struct.unpack('<H', linked_data[linked_opt+68:linked_opt+70])[0]
print(f'Subsystem:')
print(f'  test_msvc.exe: {msvc_subsystem}')
print(f'  test_exit_linked.exe: {linked_subsystem}')

msvc_num_dirs = struct.unpack('<I', msvc_data[msvc_opt+108:msvc_opt+112])[0]
linked_num_dirs = struct.unpack('<I', linked_data[linked_opt+108:linked_opt+112])[0]
print(f'NumberOfRvaAndSizes:')
print(f'  test_msvc.exe: {msvc_num_dirs}')
print(f'  test_exit_linked.exe: {linked_num_dirs}')

# Import directory
msvc_import_dir = struct.unpack('<I', msvc_data[msvc_opt+112+8:msvc_opt+112+12])[0]
linked_import_dir = struct.unpack('<I', linked_data[linked_opt+112+8:linked_opt+112+12])[0]
print(f'Import directory RVA:')
print(f'  test_msvc.exe: 0x{msvc_import_dir:08x}')
print(f'  test_exit_linked.exe: 0x{linked_import_dir:08x}')
