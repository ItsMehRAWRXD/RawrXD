#!/usr/bin/env python3
import struct
import sys

def analyze_pe(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    
    # DOS header
    dos_magic = struct.unpack('<H', data[0:2])[0]
    print(f"DOS Magic: 0x{dos_magic:04X}")
    
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    print(f"PE Offset: 0x{pe_offset:X}")
    
    # COFF header
    machine = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
    num_sections = struct.unpack('<H', data[pe_offset+6:pe_offset+8])[0]
    print(f"Machine: 0x{machine:04X}")
    print(f"Sections: {num_sections}")
    
    # Optional header
    opt_magic = struct.unpack('<H', data[pe_offset+24:pe_offset+26])[0]
    entry_point = struct.unpack('<I', data[pe_offset+28:pe_offset+32])[0]
    image_base = struct.unpack('<Q', data[pe_offset+48:pe_offset+56])[0]
    print(f"Optional Magic: 0x{opt_magic:X}")
    print(f"Entry Point RVA: 0x{entry_point:X}")
    print(f"Image Base: 0x{image_base:X}")
    
    # Data directories
    import_dir_rva = struct.unpack('<I', data[pe_offset+120+8:pe_offset+120+12])[0]
    import_dir_size = struct.unpack('<I', data[pe_offset+120+12:pe_offset+120+16])[0]
    print(f"Import Dir RVA: 0x{import_dir_rva:X}, Size: {import_dir_size}")
    
    # Section headers
    sect_hdr_offset = pe_offset + 24 + 224 + 128
    for i in range(num_sections):
        name = data[sect_hdr_offset + i*40 : sect_hdr_offset + i*40 + 8].rstrip(b'\x00').decode('ascii', errors='ignore')
        virt_size = struct.unpack('<I', data[sect_hdr_offset + i*40 + 8 : sect_hdr_offset + i*40 + 12])[0]
        virt_addr = struct.unpack('<I', data[sect_hdr_offset + i*40 + 12 : sect_hdr_offset + i*40 + 16])[0]
        raw_addr = struct.unpack('<I', data[sect_hdr_offset + i*40 + 20 : sect_hdr_offset + i*40 + 24])[0]
        chars = struct.unpack('<I', data[sect_hdr_offset + i*40 + 36 : sect_hdr_offset + i*40 + 40])[0]
        print(f"Section {name}: RVA=0x{virt_addr:X}, Size={virt_size}, Raw=0x{raw_addr:X}, Chars=0x{chars:08X}")
    
    # Check code at entry point
    text_rva = 0x1000
    text_file_offset = 0x200
    code_offset = text_file_offset
    print(f"\nCode at entry point (file offset 0x{code_offset:X}):")
    code_bytes = data[code_offset:code_offset+17]
    print(' '.join(f'{b:02X}' for b in code_bytes))
    
    # Check import directory
    idata_rva = 0x2000
    idata_file_offset = 0x400
    print(f"\nImport Directory at file offset 0x{idata_file_offset:X}:")
    idt = data[idata_file_offset:idata_file_offset+20]
    print(' '.join(f'{b:02X}' for b in idt))
    
    # Parse import directory entry
    ilt_rva = struct.unpack('<I', data[idata_file_offset:idata_file_offset+4])[0]
    name_rva = struct.unpack('<I', data[idata_file_offset+12:idata_file_offset+16])[0]
    iat_rva = struct.unpack('<I', data[idata_file_offset+16:idata_file_offset+20])[0]
    print(f"  ILT RVA: 0x{ilt_rva:X}")
    print(f"  Name RVA: 0x{name_rva:X}")
    print(f"  IAT RVA: 0x{iat_rva:X}")
    
    # Check IAT
    iat_file_offset = idata_file_offset + (iat_rva - idata_rva)
    print(f"\nIAT at file offset 0x{iat_file_offset:X}:")
    iat_entry = struct.unpack('<Q', data[iat_file_offset:iat_file_offset+8])[0]
    print(f"  IAT[0]: 0x{iat_entry:016X}")

if __name__ == '__main__':
    analyze_pe(sys.argv[1])
