#!/usr/bin/env python3
"""
Sovereign GGUF Tensor Alignment Audit
Parses ministral3.gguf and reports tensor offsets + 64-byte alignment status.
"""
import struct, sys, os

def read_string(f):
    length = struct.unpack('<Q', f.read(8))[0]
    return f.read(length)

def skip_value(f, val_type):
    """Skip a GGUF metadata value of given type."""
    if val_type == 0 or val_type == 1:   f.seek(1, 1)
    elif val_type == 2 or val_type == 3: f.seek(2, 1)
    elif val_type == 4 or val_type == 5: f.seek(4, 1)
    elif val_type == 6:                  f.seek(4, 1)
    elif val_type == 7:                  f.seek(1, 1)
    elif val_type == 8:
        length = struct.unpack('<Q', f.read(8))[0]
        f.seek(length, 1)
    elif val_type == 9:
        arr_type = struct.unpack('<I', f.read(4))[0]
        arr_len = struct.unpack('<Q', f.read(8))[0]
        for _ in range(arr_len):
            skip_value(f, arr_type)
    elif val_type == 10 or val_type == 11: f.seek(8, 1)
    elif val_type == 12:                 f.seek(8, 1)

def audit_gguf(path):
    with open(path, 'rb') as f:
        # Header
        magic, version, tensor_count, meta_count = struct.unpack('<I I Q Q', f.read(24))
        print(f"Magic:     {magic:08X} ({'GGUF' if magic == 0x46554747 else 'UNKNOWN'})")
        print(f"Version:   {version}")
        print(f"Tensors:   {tensor_count}")
        print(f"Meta KVs:  {meta_count}")
        print()

        # Skip metadata
        for i in range(meta_count):
            key = read_string(f)
            val_type = struct.unpack('<I', f.read(4))[0]
            skip_value(f, val_type)

        tensor_info_start = f.tell()
        print(f"Tensor info section starts at offset: {tensor_info_start}")
        print()

        # Read tensor info
        tensors = []
        for i in range(tensor_count):
            name = read_string(f).decode('utf-8', errors='replace')
            n_dims = struct.unpack('<I', f.read(4))[0]
            dims = struct.unpack('<' + 'Q'*n_dims, f.read(8*n_dims))
            ggml_type = struct.unpack('<I', f.read(4))[0]
            offset = struct.unpack('<Q', f.read(8))[0]
            tensors.append({
                'name': name,
                'dims': dims,
                'type': ggml_type,
                'offset': offset,
            })

        # GGUF data section starts after tensor info, aligned to 32 bytes
        data_section_start = f.tell()
        data_section_start = (data_section_start + 31) & ~31
        print(f"Data section starts at offset: {data_section_start}")
        print()

        # Report first 30 tensors
        print(f"{'Name':<50s} {'Type':>4s} {'Dims':>30s} {'FileOffset':>12s} {'64B_Align':>9s} {'512B_Align':>10s}")
        print("="*120)
        for t in tensors[:30]:
            file_offset = data_section_start + t['offset']
            align64 = (file_offset % 64 == 0)
            align512 = (file_offset % 512 == 0)
            dims_str = str(t['dims']) if len(t['dims']) <= 4 else str(t['dims'][:4]) + "..."
            print(f"{t['name']:<50s} {t['type']:>4d} {dims_str:>30s} {file_offset:>12d} {'YES' if align64 else 'NO':>9s} {'YES' if align512 else 'NO':>10s}")

        # Summary statistics
        total_tensors = len(tensors)
        aligned_64 = sum(1 for t in tensors if ((data_section_start + t['offset']) % 64 == 0))
        aligned_512 = sum(1 for t in tensors if ((data_section_start + t['offset']) % 512 == 0))
        print()
        print(f"Summary: {aligned_64}/{total_tensors} tensors are 64-byte aligned ({aligned_64*100//total_tensors}%)")
        print(f"Summary: {aligned_512}/{total_tensors} tensors are 512-byte aligned ({aligned_512*100//total_tensors}%)")

        # Check if any tensor types are unsupported by our kernel
        supported_types = {0, 1, 2, 3, 6, 7, 8, 9}  # F32, F16, Q4_0, Q4_1, Q5_0, Q5_1, Q8_0, Q8_1
        unsupported = [t for t in tensors if t['type'] not in supported_types]
        if unsupported:
            print(f"\nWARNING: {len(unsupported)} tensors use unsupported GGML types (need K-quant dequant):")
            for t in unsupported[:10]:
                print(f"  {t['name']}: type={t['type']}")
        else:
            print(f"\nAll tensors use GGML types supported by sovereign kernels.")

if __name__ == '__main__':
    path = r'D:\ministral3_q4_0.gguf'
    if not os.path.exists(path):
        print(f"File not found: {path}")
        sys.exit(1)
    audit_gguf(path)
