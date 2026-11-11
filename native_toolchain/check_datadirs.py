import struct

with open('test_exit_linked.exe', 'rb') as f:
    data = f.read()

pe_offset = struct.unpack('<I', data[60:64])[0]
coff_offset = pe_offset + 4
opt_offset = coff_offset + 20

# Data directories start at opt_offset + 112
print('Data Directories:')
for i in range(16):
    doff = opt_offset + 112 + i * 8
    rva = struct.unpack('<I', data[doff:doff+4])[0]
    size = struct.unpack('<I', data[doff+4:doff+8])[0]
    if rva != 0 or size != 0:
        print(f'  Directory {i}: RVA=0x{rva:08x}, Size={size}')

# Check import directory specifically
import_dir_off = opt_offset + 112 + 1 * 8
import_rva = struct.unpack('<I', data[import_dir_off:import_dir_off+4])[0]
import_size = struct.unpack('<I', data[import_dir_off+4:import_dir_off+8])[0]
print()
print(f'Import Directory: RVA=0x{import_rva:08x}, Size={import_size}')

# The import directory should point to the IDT
# IDT is at idata_rva = 0x3000
print(f'Expected IDT at RVA: 0x3000')
print(f'Match: {import_rva == 0x3000}')
