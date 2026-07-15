#!/usr/bin/env python3
"""
RawrXD GGUF Tensor Extractor - Working Version
Parses GGUF files and exports tensor metadata for C++ loading
"""

import struct
import sys
import json
import os

# GGUF type constants
GGUF_TYPE_UINT8 = 0
GGUF_TYPE_INT8 = 1
GGUF_TYPE_UINT16 = 2
GGUF_TYPE_INT16 = 3
GGUF_TYPE_UINT32 = 4
GGUF_TYPE_INT32 = 5
GGUF_TYPE_FLOAT32 = 6
GGUF_TYPE_UINT64 = 7
GGUF_TYPE_INT64 = 8
GGUF_TYPE_FLOAT64 = 9
GGUF_TYPE_BOOL = 10
GGUF_TYPE_STRING = 11
GGUF_TYPE_ARRAY = 12

# GGML data type constants
GGML_TYPE_F32 = 0
GGML_TYPE_F16 = 1
GGML_TYPE_Q4_0 = 2
GGML_TYPE_Q4_1 = 3
GGML_TYPE_Q5_0 = 6
GGML_TYPE_Q5_1 = 7
GGML_TYPE_Q8_0 = 8
GGML_TYPE_Q8_1 = 9
GGML_TYPE_Q2_K = 10
GGML_TYPE_Q3_K = 11
GGML_TYPE_Q4_K = 12
GGML_TYPE_Q5_K = 13
GGML_TYPE_Q6_K = 14
GGML_TYPE_Q8_K = 15

GGML_TYPE_NAMES = {
    GGML_TYPE_F32: "F32",
    GGML_TYPE_F16: "F16",
    GGML_TYPE_Q4_0: "Q4_0",
    GGML_TYPE_Q4_1: "Q4_1",
    GGML_TYPE_Q5_0: "Q5_0",
    GGML_TYPE_Q5_1: "Q5_1",
    GGML_TYPE_Q8_0: "Q8_0",
    GGML_TYPE_Q8_1: "Q8_1",
    GGML_TYPE_Q2_K: "Q2_K",
    GGML_TYPE_Q3_K: "Q3_K",
    GGML_TYPE_Q4_K: "Q4_K",
    GGML_TYPE_Q5_K: "Q5_K",
    GGML_TYPE_Q6_K: "Q6_K",
    GGML_TYPE_Q8_K: "Q8_K",
}


def read_string(f):
    """Read a GGUF string (u64 length + bytes)"""
    length = struct.unpack('<Q', f.read(8))[0]
    data = f.read(length)
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return data.decode('latin-1')


def skip_value(f, value_type):
    """Skip a GGUF value based on type"""
    if value_type == GGUF_TYPE_UINT8:
        f.read(1)
    elif value_type == GGUF_TYPE_INT8:
        f.read(1)
    elif value_type == GGUF_TYPE_UINT16:
        f.read(2)
    elif value_type == GGUF_TYPE_INT16:
        f.read(2)
    elif value_type == GGUF_TYPE_UINT32:
        f.read(4)
    elif value_type == GGUF_TYPE_INT32:
        f.read(4)
    elif value_type == GGUF_TYPE_FLOAT32:
        f.read(4)
    elif value_type == GGUF_TYPE_UINT64:
        f.read(8)
    elif value_type == GGUF_TYPE_INT64:
        f.read(8)
    elif value_type == GGUF_TYPE_FLOAT64:
        f.read(8)
    elif value_type == GGUF_TYPE_BOOL:
        f.read(1)
    elif value_type == GGUF_TYPE_STRING:
        length = struct.unpack('<Q', f.read(8))[0]
        f.read(length)
    elif value_type == GGUF_TYPE_ARRAY:
        arr_type = struct.unpack('<I', f.read(4))[0]
        arr_len = struct.unpack('<Q', f.read(8))[0]
        for _ in range(arr_len):
            skip_value(f, arr_type)
    else:
        raise ValueError(f"Unknown type: {value_type}")


def parse_gguf(filepath):
    """Parse GGUF file and return tensor metadata"""
    
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
        for i in range(metadata_kv_count):
            key = read_string(f)
            value_type = struct.unpack('<I', f.read(4))[0]
            skip_value(f, value_type)
        
        # Get current position (start of tensor info)
        tensor_info_start = f.tell()
        
        # Parse tensor info
        tensors = []
        for i in range(tensor_count):
            name = read_string(f)
            n_dims = struct.unpack('<I', f.read(4))[0]
            dims = [struct.unpack('<Q', f.read(8))[0] for _ in range(n_dims)]
            dtype = struct.unpack('<I', f.read(4))[0]
            offset = struct.unpack('<Q', f.read(8))[0]
            
            # Calculate tensor size
            num_elements = 1
            for d in dims:
                num_elements *= d
            
            # Calculate size based on dtype
            if dtype in [GGML_TYPE_Q4_0, GGML_TYPE_Q4_1]:
                blocks = (num_elements + 31) // 32
                size = blocks * (18 if dtype == GGML_TYPE_Q4_0 else 20)
            elif dtype == GGML_TYPE_Q8_0:
                blocks = (num_elements + 31) // 32
                size = blocks * 34
            elif dtype in [GGML_TYPE_Q2_K, GGML_TYPE_Q3_K, GGML_TYPE_Q4_K, 
                          GGML_TYPE_Q5_K, GGML_TYPE_Q6_K, GGML_TYPE_Q8_K]:
                if dtype == GGML_TYPE_Q2_K:
                    size = num_elements // 4 + 256
                elif dtype == GGML_TYPE_Q4_K:
                    size = num_elements // 2 + 256
                elif dtype == GGML_TYPE_Q5_K:
                    size = num_elements // 2 + 256
                elif dtype == GGML_TYPE_Q6_K:
                    size = num_elements // 2 + 256
                elif dtype == GGML_TYPE_Q8_K:
                    size = num_elements + 256
                else:
                    size = num_elements
            elif dtype == GGML_TYPE_F32:
                size = num_elements * 4
            elif dtype == GGML_TYPE_F16:
                size = num_elements * 2
            else:
                size = num_elements
            
            tensors.append({
                'name': name,
                'dims': dims,
                'dtype': dtype,
                'dtype_name': GGML_TYPE_NAMES.get(dtype, f"UNKNOWN({dtype})"),
                'offset': offset,
                'size': size,
                'num_elements': num_elements
            })
        
        # Calculate data offset (align to 32 bytes)
        data_offset = (f.tell() + 31) & ~31
        
        return {
            'version': version,
            'tensor_count': tensor_count,
            'tensors': tensors,
            'data_offset': data_offset,
            'tensor_info_start': tensor_info_start
        }


def export_tensor_index(gguf_info, output_path):
    """Export tensor index to JSON for C++ loader"""
    
    index = {
        'version': gguf_info['version'],
        'tensor_count': gguf_info['tensor_count'],
        'data_offset': gguf_info['data_offset'],
        'tensors': []
    }
    
    for t in gguf_info['tensors']:
        index['tensors'].append({
            'name': t['name'],
            'dims': t['dims'],
            'dtype': t['dtype'],
            'dtype_name': t['dtype_name'],
            'offset': t['offset'],
            'size': t['size'],
            'num_elements': t['num_elements']
        })
    
    with open(output_path, 'w') as f:
        json.dump(index, f, indent=2)
    
    print(f"\nExported tensor index to: {output_path}")
    print(f"Total tensors: {len(index['tensors'])}")
    print(f"Data offset: {index['data_offset']}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python extract_tensors.py <model.gguf> [output.json]")
        sys.exit(1)
    
    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else input_path + '.index.json'
    
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
        
        for t in gguf_info['tensors'][:10]:  # Show first 10
            print(f"\n{t['name']}")
            print(f"  Shape: {t['dims']}")
            print(f"  Type: {t['dtype_name']} ({t['dtype']})")
            print(f"  Offset: {t['offset']}, Size: {t['size']} bytes")
            print(f"  Elements: {t['num_elements']}")
        
        if len(gguf_info['tensors']) > 10:
            print(f"\n... and {len(gguf_info['tensors']) - 10} more tensors")
        
        # Export index
        export_tensor_index(gguf_info, output_path)
        
        print("\n✓ Parsing complete!")
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
