import struct
p = r'F:\rawrxd\evidence\RAWRXD_SOVEREIGN_PE_RUNTIME_001\test_exit42.exe'
d = open(p, 'rb').read()
stub = d[0xA00:0xA00 + 0x20]
print('stub', stub.hex(' '))
print('E8@4', stub[4:9].hex(' '))
print('FF15@f', stub[0x0F:0x15].hex(' '))
main_disp = struct.unpack_from('<i', stub, 5)[0]
iat_disp = struct.unpack_from('<i', stub, 0x11)[0]
stub_rva = 0x4000
print('main_target_rva', hex((stub_rva + 9 + main_disp) & 0xFFFFFFFF))
print('iat_target_rva', hex((stub_rva + 0x15 + iat_disp) & 0xFFFFFFFF))
print('text', d[0x400:0x410].hex(' '))
