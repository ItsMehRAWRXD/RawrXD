#!/usr/bin/env python3
"""
L4.1.2 Reference Extractor
Extracts token embedding from GGUF for reference comparison
"""

import struct
import sys

def read_string(f):
    """Read a length-prefixed string from file"""
    length = struct.unpack('<Q', f.read(8))[0]
    return f.read(length).decode('utf-8')

def skip_metadata_value(f, val_type):
    """Skip a metadata value based on type"""
    if val_type in [0, 1]:  # uint8, int8
        f.seek(1, 1)
    elif val_type in [2, 3]:  # uint16, int16
        f.seek(2, 1)
    elif val_type in [4, 5, 6]:  # uint32, int32, float32
        f.seek(4, 1)
    elif val_type in [7, 8, 9]:  # uint64, int64, float64
        f.seek(8, 1)
    elif val_type == 10:  # bool
        f.seek(1, 1)
    elif val_type == 11:  # string
        length = struct.unpack('<Q', f.read(8))[0]
        f.seek(length, 1)
    elif val_type == 12:  # array
        arr_type = struct.unpack('<I', f.read(4))[0]
        arr_len = struct.unpack('<Q', f.read(8))[0]
        for _ in range(arr_len):
            skip_metadata_value(f, arr_type)

def fp16_to_fp32(fp16):
    """Convert FP16 to FP32"""
    sign = (fp16 >> 15) & 0x1
    exp = (fp16 >> 10) & 0x1F
    mant = fp16 & 0x3FF
    
    if exp == 0:
        if mant == 0:
            return -0.0 if sign else 0.0
        # Subnormal
        val = mant / 1024.0
        return -val * 0.00006103515625 if sign else val * 0.00006103515625
    if exp == 0x1F:
        if mant == 0:
            return float('-inf') if sign else float('inf')
        return float('nan')
    
    # Normal
    exp32 = exp + 112
    mant32 = mant << 13
    fp32 = (sign << 31) | (exp32 << 23) | mant32
    return struct.unpack('f', struct.pack('I', fp32))[0]

def extract_token_embedding(gguf_path, token_id):
    """Extract token embedding from GGUF file"""
    
    with open(gguf_path, 'rb') as f:
        # Read header
        magic = struct.unpack('<I', f.read(4))[0]
        version = struct.unpack('<I', f.read(4))[0]
        n_tensors = struct.unpack('<Q', f.read(8))[0]
        n_metadata = struct.unpack('<Q', f.read(8))[0]
        
        if magic != 0x46554747:  # "GGUF"
            print("Invalid GGUF magic")
            return None
        
        print(f"GGUF Version: {version}")
        print(f"Tensors: {n_tensors}, Metadata: {n_metadata}")
        
        # Skip metadata
        for _ in range(n_metadata):
            key = read_string(f)
            val_type = struct.unpack('<I', f.read(4))[0]
            skip_metadata_value(f, val_type)
        
        # Read tensor info
        tensor_offset = None
        tensor_type = None
        n_dims = None
        dims = None
        
        for _ in range(n_tensors):
            name = read_string(f)
            n_dims = struct.unpack('<I', f.read(4))[0]
            dims = [struct.unpack('<Q', f.read(8))[0] for _ in range(n_dims)]
            tensor_type = struct.unpack('<I', f.read(4))[0]
            offset = struct.unpack('<Q', f.read(8))[0]
            
            if name == "token_embd.weight":
                tensor_offset = offset
                print(f"\nFound token_embd.weight:")
                print(f"  Dims: {dims}")
                print(f"  Type: {tensor_type} (Q4_0 = 2)")
                print(f"  Offset: {offset}")
                break
        
        if tensor_offset is None:
            print("token_embd.weight not found")
            return None
        
        # Calculate tensor data start (align to 32 bytes)
        current_pos = f.tell()
        tensor_data_start = (current_pos + 31) & ~31
        
        # For Q4_0: each block is 18 bytes (2 bytes scale + 16 bytes quants for 32 values)
        embedding_dim = dims[0]
        n_blocks = embedding_dim // 32
        row_size = n_blocks * 18
        
        print(f"\nExtraction parameters:")
        print(f"  Token ID: {token_id}")
        print(f"  Embedding dim: {embedding_dim}")
        print(f"  Blocks per row: {n_blocks}")
        print(f"  Row size: {row_size} bytes")
        
        # Seek to token row
        row_offset = tensor_data_start + tensor_offset + (token_id * row_size)
        f.seek(row_offset)
        
        # Read and dequantize
        embedding = []
        
        for _ in range(n_blocks):
            # Read block
            scale = struct.unpack('<H', f.read(2))[0]
            quants = f.read(16)
            
            scale_f = fp16_to_fp32(scale)
            
            for i in range(16):
                byte = quants[i]
                low = (byte & 0x0F) - 8
                high = ((byte >> 4) & 0x0F) - 8
                
                embedding.append(low * scale_f)
                embedding.append(high * scale_f)
        
        return embedding

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <gguf_file> <token_id>")
        sys.exit(1)
    
    gguf_path = sys.argv[1]
    token_id = int(sys.argv[2])
    
    embedding = extract_token_embedding(gguf_path, token_id)
    
    if embedding is None:
        sys.exit(1)
    
    # Save to binary file
    out_path = f"llamacpp_token_{token_id}.bin"
    with open(out_path, 'wb') as f:
        for val in embedding:
            f.write(struct.pack('f', val))
    
    print(f"\nReference embedding saved to: {out_path}")
    print(f"  Size: {len(embedding) * 4} bytes")
    print(f"  Min: {min(embedding)}")
    print(f"  Max: {max(embedding)}")
    print(f"  Mean: {sum(embedding) / len(embedding)}")

if __name__ == "__main__":
    main()
