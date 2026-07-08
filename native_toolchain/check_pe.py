import struct

with open('test_exit_linked.exe', 'rb') as f:
    data = f.read()

# Check PE structure
print('PE structure check:')
print(f'File size: {len(data)} bytes')

# DOS header
dos_magic = struct.unpack('<H', data[0:2])[0]
print(f'DOS magic: 0x{dos_magic:04x}')

pe_offset = struct.unpack('<I', data[60:64])[0]
print(f'PE offset: 0x{pe_offset:x}')

# PE signature
pe_sig = struct.unpack('<I', data[pe_offset:pe_offset+4])[0]
print(f'PE signature: 0x{pe_sig:08x}')

# COFF header
coff_offset = pe_offset + 4
machine = struct.unpack('<H', data[coff_offset:coff_offset+2])[0]
print(f'Machine: 0x{machine:04x}')

num_sections = struct.unpack('<H', data[coff_offset+2:coff_offset+4])[0]
print(f'Number of sections: {num_sections}')

# Optional header
opt_offset = coff_offset + 24
magic = struct.unpack('<H', data[opt_offset:opt_offset+2])[0]
print(f'Optional header magic: 0x{magic:04x} (expected 0x020b)')

entry_point = struct.unpack('<I', data[opt_offset+16:opt_offset+20])[0]
print(f'Entry point RVA: 0x{entry_point:08x}')

image_base = struct.unpack('<Q', data[opt_offset+24:opt_offset+32])[0]
print(f'Image base: 0x{image_base:016x}')

subsystem = struct.unpack('<H', data[opt_offset+68:opt_offset+70])[0]
print(f'Subsystem: {subsystem} (expected 3)')

# Check section headers
sect_offset = opt_offset + 112 + 128  # opt header + data directories
print()
print('Section headers:')
for i in range(num_sections):
    off = sect_offset + i * 40
    name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
    vsize = struct.unpack('<I', data[off+8:off+12])[0]
    vrva = struct.unpack('<I', data[off+12:off+16])[0]
    rsize = struct.unpack('<I', data[off+16:off+20])[0]
    rptr = struct.unpack('<I', data[off+20:off+24])[0]
    print(f'  Section "{name}": VSize={vsize}, VRva=0x{vrva:08x}, RSize={rsize}, RPtr=0x{rptr:08x}')
