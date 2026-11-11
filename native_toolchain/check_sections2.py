import struct

with open('test_exit_linked.exe', 'rb') as f:
    data = f.read()

# Calculate section header offset
# PE signature at 0x40
# COFF header at 0x44 (20 bytes)
# Optional header at 0x58 (112 bytes)
# Data directories at 0xC8 (128 bytes = 16 * 8)
# Section headers at 0x148

sect_offset = 0x148
print(f'Section headers at 0x{sect_offset:x}:')

for i in range(2):
    off = sect_offset + i * 40
    name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
    vsize = struct.unpack('<I', data[off+8:off+12])[0]
    vrva = struct.unpack('<I', data[off+12:off+16])[0]
    rsize = struct.unpack('<I', data[off+16:off+20])[0]
    rptr = struct.unpack('<I', data[off+20:off+24])[0]
    print(f'  Section "{name}": VSize={vsize}, VRva=0x{vrva:08x}, RSize={rsize}, RPtr=0x{rptr:08x}')
