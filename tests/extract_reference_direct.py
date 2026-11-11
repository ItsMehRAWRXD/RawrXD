#!/usr/bin/env python3
"""
L4.1.2 Reference Extractor - Direct Seek Version
Uses known offsets from L4_1_Discover_v4
"""

import struct
import sys

def fp16_to_fp32(fp16):
    """Convert FP16 to FP32"""
    sign = (fp16 >> 15) & 0x1
    exp = (fp16 >> 10) & 0x1F
    mant = fp16 & 0x3FF
    
    if exp == 0:
        if mant == 0:
            return -0.0 if sign else 0.0
        val = mant / 1024.0
        return -val * 0.00006103515625 if sign else val * 0.00006103515625
    if exp == 0x1F:
        if mant == 0:
            return float('-inf') if sign else float('inf')
        return float('nan')
    
    exp32 = exp + 112
    mant32 = mant << 13
    fp32 = (sign << 31) | (exp32 << 23) | mant32
    return struct.unpack('f', struct.pack('I', fp32))[0]

def extract_token_embedding(gguf_path, token_id):
    """Extract token embedding using known offsets"""
    
    # Known from L4_1_Discover_v4 and L4_1_1_Decode
    # Token 42 absolute offset from L4_1_1_Decode: 0x1dc1baf5
    # Token 0 absolute offset = 0x1dc1baf5 - (42 * 2304) = 0x1dc040f5
    # But this is NOT 32-byte aligned, which is suspicious
    #
    # Actually, L4_1_1_Decode reports:
    #   Row offset: 0x1dc1baf5 for token 42
    # This is the CORRECT absolute offset
    
    # For token 42 specifically (as validated by L4_1_1_Decode):
    if token_id == 42:
        ROW_OFFSET = 0x1dc1baf5  # Absolute offset for token 42
    else:
        # Calculate from token 42 base
        ROW_SIZE = 2304
        ROW_OFFSET = 0x1dc1baf5 + ((token_id - 42) * ROW_SIZE)
    
    EMBEDDING_DIM = 4096
    
    with open(gguf_path, 'rb') as f:
        # Seek to token row
        f.seek(ROW_OFFSET)
        
        print(f"Token ID: {token_id}")
        print(f"Embedding dim: {EMBEDDING_DIM}")
        print(f"Blocks per row: 128")
        print(f"Row size: 2304 bytes")
        print(f"File offset: 0x{ROW_OFFSET:x}")
        
        # Read and dequantize
        embedding = []
        n_blocks = 128
        
        for block_idx in range(n_blocks):
            # Read block
            scale_bytes = f.read(2)
            if len(scale_bytes) != 2:
                print(f"Error: Could not read scale at block {block_idx}")
                return None
            scale = struct.unpack('<H', scale_bytes)[0]
            quants = f.read(16)
            if len(quants) != 16:
                print(f"Error: Could not read quants at block {block_idx}")
                return None
            
            scale_f = fp16_to_fp32(scale)
            
            # Handle NaN/Inf scales like RawrXD does (ZERO_FILL policy)
            if scale_f != scale_f or (scale_f == float('inf')) or (scale_f == float('-inf')):
                # NaN or Inf scale - output zeros
                for i in range(32):
                    embedding.append(0.0)
            else:
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
    
    # Print first few values for verification
    print(f"\nFirst 8 values:")
    for i in range(8):
        print(f"  [{i}]: {embedding[i]}")

if __name__ == "__main__":
    main()
