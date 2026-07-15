import struct

with open('test_exit_linked.exe', 'rb') as f:
    data = f.read()

# Section headers at 0x140
sect_offset = 0x140

print('Section headers at 0x140:')
for i in range(2):
    off = sect_offset + i * 40
    name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
    vsize = struct.unpack('<I', data[off+8:off+12])[0]
    vrva = struct.unpack('<I', data[off+12:off+16])[0]
    rsize = struct.unpack('<I', data[off+16:off+20])[0]
    rptr = struct.unpack('<I', data[off+20:off+24])[0]
    print(f'  Section "{name}": VSize={vsize}, VRva=0x{vrva:08x}, RSize={rsize}, RPtr=0x{rptr:08x}')
