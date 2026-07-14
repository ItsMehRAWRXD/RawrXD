#!/usr/bin/env python3
"""
RawrXD GGUF Binary Index Generator
Generates a simple binary index file for C++ tensor loader
"""

import struct
import sys
import os

def read_string(f):
    """Read a GGUF string (u64 length + bytes)"""
    length = struct.unpack('<Q', f.read(8))[0]
    return f.read(length)

def skip_value(f, value_type):
    """Skip a GGUF value based on type"""
    if value_type in [0, 1, 10]:  # UINT8, INT8, BOOL
        f.read(1)
    elif value_type in [2, 3]:  # UINT16, INT16
        f.read(2)
    elif value_type in [4, 5, 6]:  # UINT32, INT32, FLOAT32
        f.read(4)
    elif value_type in [7, 8, 9]:  # UINT64, INT64, FLOAT64
        f.read(8)
    elif value_type == 11:  # STRING
        length = struct.unpack('<Q', f.read(8))[0]
        f.read(length)
    elif value_type == 12:  # ARRAY
        arr_type = struct.unpack('<I', f.read(4))[0]
        arr_len = struct.unpack('<Q', f.read(8))[0]
        for _ in range(arr_len):
            skip_value(f, arr_type)

def parse_gguf(filepath):
    """Parse GGUF and return tensor info"""
    
    with open(filepath, 'rb') as f:
        # Read header
        magic = f.read(4)
        if magic != b'GGUF':
            raise ValueError(f"Invalid magic: {magic}")
        
        version = struct.unpack('<I', f.read(4))[0]
        tensor_count = struct.unpack('<Q', f.read(8))[0]
        metadata_kv_count = struct.unpack('<Q', f.read(8))[0]
        
        print(f"GGUF Version: {version}")
        print(f"Tensor Count: {tensor_count}")
        print(f"Metadata Count: {metadata_kv_count}")
        
        # Skip metadata
        for _ in range(metadata_kv_count):
            key = read_string(f)
            value_type = struct.unpack('<I', f.read(4))[0]
            skip_value(f, value_type)
        
        # Get data offset
        data_offset = (f.tell() + 31) & ~31
        
        # Parse tensor info
        tensors = []
        for i in range(tensor_count):
            name = read_string(f).decode('utf-8', errors='replace')
            n_dims = struct.unpack('<I', f.read(4))[0]
            dims = [struct.unpack('<Q', f.read(8))[0] for _ in range(n_dims)]
            dtype = struct.unpack('<I', f.read(4))[0]
            offset = struct.unpack('<Q', f.read(8))[0]
            
            tensors.append({
                'name': name,
                'dims': dims,
                'dtype': dtype,
                'offset': offset
            })
        
        return {
            'version': version,
            'tensor_count': tensor_count,
            'data_offset': data_offset,
            'tensors': tensors
        }

def write_binary_index(gguf_info, output_path):
    """Write binary index file"""
    
    with open(output_path, 'wb') as f:
        # Header
        f.write(struct.pack('<I', gguf_info['version']))
        f.write(struct.pack('<Q', gguf_info['tensor_count']))
        f.write(struct.pack('<Q', gguf_info['data_offset']))
        
        # Tensors
        for t in gguf_info['tensors']:
            # Name length + name
            name_bytes = t['name'].encode('utf-8')
            f.write(struct.pack('<Q', len(name_bytes)))
            f.write(name_bytes)
            
            # Num dims + dims
            f.write(struct.pack('<I', len(t['dims'])))
            for d in t['dims']:
                f.write(struct.pack('<Q', d))
            
            # Dtype + offset
            f.write(struct.pack('<I', t['dtype']))
            f.write(struct.pack('<Q', t['offset']))
    
    print(f"\nExported binary index to: {output_path}")
    print(f"Total tensors: {gguf_info['tensor_count']}")
    print(f"Data offset: {gguf_info['data_offset']}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python generate_index.py <model.gguf> [output.bin]")
        sys.exit(1)
    
    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else input_path + '.index.bin'
    
    if not os.path.exists(input_path):
        print(f"Error: File not found: {input_path}")
        sys.exit(1)
    
    print(f"Parsing: {input_path}")
    print("=" * 60)
    
    try:
        gguf_info = parse_gguf(input_path)
        
        # Print summary
        print("\n" + "=" * 60)
        print("TENSOR SUMMARY")
        print("=" * 60)
        
        for t in gguf_info['tensors'][:10]:
            print(f"\n{t['name']}")
            print(f"  Shape: {t['dims']}")
            print(f"  Type: {t['dtype']}")
            print(f"  Offset: {t['offset']}")
        
        if len(gguf_info['tensors']) > 10:
            print(f"\n... and {len(gguf_info['tensors']) - 10} more tensors")
        
        # Write binary index
        write_binary_index(gguf_info, output_path)
        
        print("\n✓ Index generation complete!")
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
