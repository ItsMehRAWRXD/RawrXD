#!/usr/bin/env python3
"""
create_test_model.py - Create a minimal test GGUF model for validation

This creates a minimal but valid GGUF file with:
- Proper GGUF magic and header
- Minimal metadata
- One small tensor (for testing)

Usage:
    python create_test_model.py output.gguf
    python create_test_model.py output.gguf --verbose
"""

import struct
import sys
import argparse


def write_string(f, s):
    """Write a length-prefixed string to file"""
    encoded = s.encode('utf-8')
    f.write(struct.pack('<Q', len(encoded)))
    f.write(encoded)


def write_array_header(f, elem_type, count):
    """Write array type and count"""
    f.write(struct.pack('<I', elem_type))  # Element type
    f.write(struct.pack('<Q', count))       # Element count


def create_test_gguf(filename, verbose=False):
    """Create a minimal test GGUF file"""
    
    if verbose:
        print(f"Creating test GGUF: {filename}")
    
    with open(filename, 'wb') as f:
        # === HEADER ===
        # Magic: "GGUF" in little-endian
        f.write(b'GGUF')
        
        # Version: 3
        f.write(struct.pack('<I', 3))
        
        # Tensor count: 1 (one small test tensor)
        tensor_count = 1
        f.write(struct.pack('<Q', tensor_count))
        
        # Metadata KV count: 3 (minimal metadata)
        metadata_count = 3
        f.write(struct.pack('<Q', metadata_count))
        
        if verbose:
            print(f"  Header written: version=3, tensors={tensor_count}, metadata={metadata_count}")
        
        # === METADATA ===
        # Key 1: general.architecture
        write_string(f, "general.architecture")
        f.write(struct.pack('<I', 8))  # Type: string
        write_string(f, "test")
        
        # Key 2: general.name
        write_string(f, "general.name")
        f.write(struct.pack('<I', 8))  # Type: string
        write_string(f, "Test Model")
        
        # Key 3: test.value (uint32)
        write_string(f, "test.value")
        f.write(struct.pack('<I', 4))  # Type: uint32
        f.write(struct.pack('<I', 42))
        
        if verbose:
            print(f"  Metadata written: {metadata_count} entries")
        
        # === TENSOR INFO ===
        # Tensor name
        write_string(f, "test_tensor")
        
        # Number of dimensions
        f.write(struct.pack('<I', 1))  # 1D tensor
        
        # Dimensions (10 elements)
        f.write(struct.pack('<Q', 10))
        
        # Tensor type (0 = FP32)
        f.write(struct.pack('<I', 0))
        
        # Tensor offset (will be calculated)
        # For now, write placeholder - we'll fix this later
        tensor_offset_placeholder = f.tell()
        f.write(struct.pack('<Q', 0))  # Placeholder
        
        if verbose:
            print(f"  Tensor info written: test_tensor[10] (FP32)")
        
        # === ALIGNMENT ===
        # Align to 32-byte boundary
        current_pos = f.tell()
        padding = (32 - (current_pos % 32)) % 32
        f.write(b'\x00' * padding)
        
        # Now we know the data offset
        data_offset = f.tell()
        
        # Go back and fix the tensor offset
        f.seek(tensor_offset_placeholder)
        f.write(struct.pack('<Q', data_offset))
        f.seek(data_offset)
        
        if verbose:
            print(f"  Data offset: {data_offset} (aligned to 32 bytes)")
        
        # === TENSOR DATA ===
        # Write 10 FP32 values
        for i in range(10):
            f.write(struct.pack('<f', float(i) * 0.1))
        
        if verbose:
            print(f"  Tensor data written: 10 FP32 values")
        
        # === END OF FILE ===
        file_size = f.tell()
        
    if verbose:
        print(f"\nGGUF file created successfully!")
        print(f"  File: {filename}")
        print(f"  Size: {file_size} bytes")
        print(f"  Tensors: {tensor_count}")
        print(f"  Metadata: {metadata_count}")
    else:
        print(f"Created: {filename} ({file_size} bytes)")
    
    return 0


def verify_gguf(filename):
    """Verify the created GGUF file"""
    print(f"\nVerifying: {filename}")
    
    with open(filename, 'rb') as f:
        # Read magic
        magic = f.read(4)
        if magic != b'GGUF':
            print(f"  ERROR: Invalid magic: {magic}")
            return 1
        print(f"  Magic: GGUF ✓")
        
        # Read version
        version = struct.unpack('<I', f.read(4))[0]
        print(f"  Version: {version}")
        
        # Read counts
        tensor_count = struct.unpack('<Q', f.read(8))[0]
        metadata_count = struct.unpack('<Q', f.read(8))[0]
        print(f"  Tensors: {tensor_count}")
        print(f"  Metadata: {metadata_count}")
        
        # Skip metadata
        for i in range(metadata_count):
            # Read key
            key_len = struct.unpack('<Q', f.read(8))[0]
            key = f.read(key_len).decode('utf-8')
            
            # Read type
            value_type = struct.unpack('<I', f.read(4))[0]
            
            # Skip value based on type
            if value_type == 8:  # String
                str_len = struct.unpack('<Q', f.read(8))[0]
                f.seek(str_len, 1)
            elif value_type == 4:  # uint32
                f.seek(4, 1)
        
        # Read tensor info
        for i in range(tensor_count):
            name_len = struct.unpack('<Q', f.read(8))[0]
            name = f.read(name_len).decode('utf-8')
            n_dims = struct.unpack('<I', f.read(4))[0]
            dims = []
            for j in range(n_dims):
                dims.append(struct.unpack('<Q', f.read(8))[0])
            tensor_type = struct.unpack('<I', f.read(4))[0]
            offset = struct.unpack('<Q', f.read(8))[0]
            
            print(f"  Tensor '{name}': shape={dims}, type={tensor_type}, offset={offset}")
        
        print(f"  Verification: PASSED ✓")
    
    return 0


def main():
    parser = argparse.ArgumentParser(description='Create a minimal test GGUF model')
    parser.add_argument('output', help='Output filename')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--verify', action='store_true', help='Verify after creation')
    
    args = parser.parse_args()
    
    # Create the model
    result = create_test_gguf(args.output, args.verbose)
    if result != 0:
        return result
    
    # Verify if requested
    if args.verify:
        result = verify_gguf(args.output)
    
    return result


if __name__ == '__main__':
    sys.exit(main())
