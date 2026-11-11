#!/usr/bin/env python3
"""
Minimal GGUF Generator for Model Stack Integration Validation
Creates a tiny GGUF file with constant weights for predictable inference math.

This generates a "Hello World" GGUF that:
1. Has constant weights (all 1.0 or 0.0)
2. Has a minimal vocabulary (just enough for "Hello, world!")
3. Produces deterministic output for parity testing
"""

import struct
import sys
from pathlib import Path

# GGUF Constants
GGUF_MAGIC = 0x46554747  # "GGUF"
GGUF_VERSION = 3

# GGML Types
GGML_TYPE_F32 = 0
GGML_TYPE_F16 = 1
GGML_TYPE_Q4_0 = 2
GGML_TYPE_Q4_1 = 3

# Metadata Types
GGUF_TYPE_UINT8 = 0
GGUF_TYPE_INT8 = 1
GGUF_TYPE_UINT16 = 2
GGUF_TYPE_INT16 = 3
GGUF_TYPE_UINT32 = 4
GGUF_TYPE_INT32 = 5
GGUF_TYPE_FLOAT32 = 6
GGUF_TYPE_BOOL = 7
GGUF_TYPE_STRING = 8
GGUF_TYPE_ARRAY = 9
GGUF_TYPE_UINT64 = 10
GGUF_TYPE_INT64 = 11
GGUF_TYPE_FLOAT64 = 12

def write_string(f, s):
    """Write a GGUF string (length + data)"""
    encoded = s.encode('utf-8')
    f.write(struct.pack('<Q', len(encoded)))
    f.write(encoded)

def write_metadata_kv(f, key, value, value_type):
    """Write a metadata key-value pair"""
    write_string(f, key)
    f.write(struct.pack('<I', value_type))
    
    if value_type == GGUF_TYPE_STRING:
        write_string(f, value)
    elif value_type == GGUF_TYPE_UINT32:
        f.write(struct.pack('<I', value))
    elif value_type == GGUF_TYPE_INT32:
        f.write(struct.pack('<i', value))
    elif value_type == GGUF_TYPE_FLOAT32:
        f.write(struct.pack('<f', value))
    elif value_type == GGUF_TYPE_BOOL:
        f.write(struct.pack('<?', value))
    elif value_type == GGUF_TYPE_UINT64:
        f.write(struct.pack('<Q', value))
    elif value_type == GGUF_TYPE_INT64:
        f.write(struct.pack('<q', value))
    elif value_type == GGUF_TYPE_FLOAT64:
        f.write(struct.pack('<d', value))

def write_tensor_info(f, name, dims, ggml_type):
    """Write tensor information"""
    write_string(f, name)
    f.write(struct.pack('<I', len(dims)))
    for dim in dims:
        f.write(struct.pack('<Q', dim))
    f.write(struct.pack('<I', ggml_type))
    f.write(struct.pack('<Q', 0))  # offset (will be filled later)

def generate_minimal_gguf(output_path, vocab_size=256, embed_dim=64, num_layers=1, num_heads=2):
    """
    Generate a minimal GGUF file with constant weights.
    
    Args:
        output_path: Path to write the GGUF file
        vocab_size: Vocabulary size (default 256 for ASCII)
        embed_dim: Embedding dimension (default 64 for minimal)
        num_layers: Number of transformer layers (default 1)
        num_heads: Number of attention heads (default 2)
    """
    
    with open(output_path, 'wb') as f:
        # Write header
        f.write(struct.pack('<I', GGUF_MAGIC))
        f.write(struct.pack('<I', GGUF_VERSION))
        f.write(struct.pack('<Q', 0))  # tensor_count (will be updated)
        f.write(struct.pack('<Q', 0))  # metadata_kv_count (will be updated)
        
        # Write metadata
        metadata = [
            ("general.architecture", "transformer", GGUF_TYPE_STRING),
            ("general.name", "minimal_test_model", GGUF_TYPE_STRING),
            ("general.quantization_version", 0, GGUF_TYPE_UINT32),
            ("transformer.context_length", 128, GGUF_TYPE_UINT32),
            ("transformer.embedding_length", embed_dim, GGUF_TYPE_UINT32),
            ("transformer.block_count", num_layers, GGUF_TYPE_UINT32),
            ("transformer.attention.head_count", num_heads, GGUF_TYPE_UINT32),
            ("transformer.attention.head_count_kv", num_heads, GGUF_TYPE_UINT32),
            ("transformer.feed_forward_length", embed_dim * 4, GGUF_TYPE_UINT32),
            ("vocab_size", vocab_size, GGUF_TYPE_UINT32),
        ]
        
        # Write metadata count
        tensor_count_pos = f.tell() - 16
        f.seek(tensor_count_pos)
        f.write(struct.pack('<Q', 0))  # tensor_count (placeholder)
        f.write(struct.pack('<Q', len(metadata)))
        
        # Write metadata
        for key, value, value_type in metadata:
            write_metadata_kv(f, key, value, value_type)
        
        # Write vocabulary (minimal: just ASCII + special tokens)
        vocab_start = f.tell()
        for i in range(vocab_size):
            if i < 128:
                # ASCII characters
                write_string(f, chr(i))
            else:
                # Special tokens
                write_string(f, f"<special_{i}>")
        
        # Define tensors
        tensors = [
            ("token_embd.weight", [vocab_size, embed_dim], GGML_TYPE_F32),
            ("output_norm.weight", [embed_dim], GGML_TYPE_F32),
            ("output.weight", [vocab_size, embed_dim], GGML_TYPE_F32),
        ]
        
        # Add layer tensors
        for layer in range(num_layers):
            tensors.extend([
                (f"blk.{layer}.attn_norm.weight", [embed_dim], GGML_TYPE_F32),
                (f"blk.{layer}.attn_q.weight", [embed_dim, embed_dim], GGML_TYPE_F32),
                (f"blk.{layer}.attn_k.weight", [embed_dim, embed_dim], GGML_TYPE_F32),
                (f"blk.{layer}.attn_v.weight", [embed_dim, embed_dim], GGML_TYPE_F32),
                (f"blk.{layer}.attn_output.weight", [embed_dim, embed_dim], GGML_TYPE_F32),
                (f"blk.{layer}.ffn_norm.weight", [embed_dim], GGML_TYPE_F32),
                (f"blk.{layer}.ffn_up.weight", [embed_dim, embed_dim * 4], GGML_TYPE_F32),
                (f"blk.{layer}.ffn_down.weight", [embed_dim * 4, embed_dim], GGML_TYPE_F32),
            ])
        
        # Write tensor info
        tensor_info_start = f.tell()
        f.seek(tensor_count_pos)
        f.write(struct.pack('<Q', len(tensors)))
        f.seek(tensor_info_start)
        
        for name, dims, ggml_type in tensors:
            write_tensor_info(f, name, dims, ggml_type)
        
        # Write tensor data (all constant weights = 1.0)
        tensor_data_start = f.tell()
        
        # Align to 32 bytes (GGUF requirement)
        alignment = 32
        padding = (alignment - (tensor_data_start % alignment)) % alignment
        f.write(b'\x00' * padding)
        tensor_data_start += padding
        
        # Calculate total tensor size
        total_elements = 0
        for name, dims, ggml_type in tensors:
            elements = 1
            for dim in dims:
                elements *= dim
            total_elements += elements
        
        # Write all weights as constant 1.0 (for predictable math)
        for _ in range(total_elements):
            f.write(struct.pack('<f', 1.0))
        
        # Update tensor offsets
        current_offset = 0
        f.seek(tensor_info_start)
        for name, dims, ggml_type in tensors:
            f.seek(f.tell() + len(name.encode('utf-8')) + 8 + len(dims) * 8 + 4)  # Skip to offset field
            f.write(struct.pack('<Q', current_offset))
            elements = 1
            for dim in dims:
                elements *= dim
            current_offset += elements * 4  # float32 = 4 bytes
        
        print(f"Generated minimal GGUF: {output_path}")
        print(f"  Vocab size: {vocab_size}")
        print(f"  Embed dim: {embed_dim}")
        print(f"  Layers: {num_layers}")
        print(f"  Heads: {num_heads}")
        print(f"  Tensors: {len(tensors)}")
        print(f"  Total parameters: {total_elements:,}")
        print(f"  File size: {Path(output_path).stat().st_size:,} bytes")

if __name__ == "__main__":
    output_path = sys.argv[1] if len(sys.argv) > 1 else "test_model.gguf"
    generate_minimal_gguf(output_path)