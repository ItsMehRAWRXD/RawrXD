#!/usr/bin/env python3
"""Analyze GGUF tensor table structure"""
import struct
import sys

def analyze_gguf(filepath):
    with open(filepath, 'rb') as f:
        # Read header
        magic = struct.unpack('<I', f.read(4))[0]
        version = struct.unpack('<I', f.read(4))[0]
        tensor_count = struct.unpack('<Q', f.read(8))[0]
        metadata_count = struct.unpack('<Q', f.read(8))[0]
        
        print(f"Magic: 0x{magic:08X} (GGUF=0x46554747)")
        print(f"Version: {version}")
        print(f"Tensor count: {tensor_count}")
        print(f"Metadata count: {metadata_count}")
        
        # Skip metadata
        for i in range(min(metadata_count, 1000)):
            key_len = struct.unpack('<Q', f.read(8))[0]
            key = f.read(key_len)
            val_type = struct.unpack('<I', f.read(4))[0]
            
            if val_type == 0 or val_type == 1: f.read(1)
            elif val_type == 2 or val_type == 3: f.read(2)
            elif val_type == 4 or val_type == 5 or val_type == 6: f.read(4)
            elif val_type == 10 or val_type == 11 or val_type == 12: f.read(8)
            elif val_type == 7: f.read(1)
            elif val_type == 8:
                str_len = struct.unpack('<Q', f.read(8))[0]
                f.read(str_len)
            elif val_type == 9:
                elem_type = struct.unpack('<I', f.read(4))[0]
                count = struct.unpack('<Q', f.read(8))[0]
                for _ in range(count):
                    if elem_type == 0 or elem_type == 1: f.read(1)
                    elif elem_type == 2 or elem_type == 3: f.read(2)
                    elif elem_type == 4 or elem_type == 5 or elem_type == 6: f.read(4)
                    elif elem_type == 10 or elem_type == 11 or elem_type == 12: f.read(8)
                    elif elem_type == 7: f.read(1)
                    elif elem_type == 8:
                        str_len = struct.unpack('<Q', f.read(8))[0]
                        f.read(str_len)
        
        tensor_data_start = f.tell()
        print(f"\nTensor data section starts at: {tensor_data_start}")
        
        # Read all tensor descriptors
        tensors = []
        for i in range(tensor_count):
            name_len = struct.unpack('<Q', f.read(8))[0]
            name = f.read(name_len).decode('utf-8')
            n_dims = struct.unpack('<I', f.read(4))[0]
            shape = []
            for _ in range(n_dims):
                shape.append(struct.unpack('<Q', f.read(8))[0])
            type_val = struct.unpack('<I', f.read(4))[0]
            offset = struct.unpack('<Q', f.read(8))[0]
            tensors.append({
                'name': name,
                'type': type_val,
                'shape': shape,
                'offset': offset,
                'idx': i
            })
        
        # Show last 10 tensors
        print("\nLast 10 tensors in file order:")
        for t in tensors[-10:]:
            print(f"  [{t['idx']}] {t['name']}: type={t['type']}, shape={t['shape']}, rel_offset={t['offset']}")
        
        # Check if offsets are monotonically increasing
        offsets = [t['offset'] for t in tensors]
        is_sorted = offsets == sorted(offsets)
        print(f"\nOffsets are sorted by tensor index: {is_sorted}")
        
        # Find max offset
        max_offset = max(offsets)
        max_tensor = [t for t in tensors if t['offset'] == max_offset][0]
        print(f"Max relative offset: {max_offset} (tensor: {max_tensor['name']})")
        print(f"File size: 2176177120")
        print(f"Absolute offset would be: {tensor_data_start + max_offset}")
        
        # Check for gaps/overlaps
        sorted_tensors = sorted(tensors, key=lambda x: x['offset'])
        print("\nTensors sorted by offset (last 10):")
        for t in sorted_tensors[-10:]:
            print(f"  [{t['idx']}] {t['name']}: rel_offset={t['offset']}")

if __name__ == "__main__":
    analyze_gguf(r"F:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf")
