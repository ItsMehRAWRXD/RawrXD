#!/usr/bin/env python3
"""
generate_embedding_golden.py
Generate golden vectors for embedding stage using reference implementation
"""

import numpy as np
import struct
import hashlib
from pathlib import Path

def compute_sha256(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"

def main():
    print("=" * 60)
    print("  Embedding Golden Vector Generator")
    print("=" * 60)
    
    # Configuration
    vocab_size = 32000
    hidden_dim = 4096
    batch_size = 1
    seq_len = 5
    
    # Fixed seed for reproducibility
    np.random.seed(42)
    
    # Generate embedding weights (same as C++ implementation)
    embedding_weights = (np.random.rand(vocab_size, hidden_dim).astype(np.float32) - 0.5) * 0.02
    
    # Input tokens
    input_tokens = np.array([1, 2, 3, 4, 5], dtype=np.int32)
    
    # Execute embedding lookup
    output = embedding_weights[input_tokens]  # [5, 4096]
    
    # Save input
    input_path = Path("val-019/vectors/embedding_input.bin")
    with open(input_path, 'wb') as f:
        f.write(input_tokens.tobytes())
    input_checksum = compute_sha256(input_tokens.tobytes())
    
    # Save expected output
    output_path = Path("val-019/vectors/embedding_expected.bin")
    with open(output_path, 'wb') as f:
        f.write(output.tobytes())
    output_checksum = compute_sha256(output.tobytes())
    
    print(f"\n[INPUT]")
    print(f"  Shape: {input_tokens.shape}")
    print(f"  Tokens: {input_tokens}")
    print(f"  Checksum: {input_checksum}")
    
    print(f"\n[OUTPUT]")
    print(f"  Shape: {output.shape}")
    print(f"  Dtype: float32")
    print(f"  Checksum: {output_checksum}")
    print(f"  Sample values: {output[0, :5]}")
    
    print(f"\n[FILES]")
    print(f"  Input:  {input_path}")
    print(f"  Output: {output_path}")
    
    # Update metadata
    print(f"\n[METADATA UPDATE]")
    print(f"  Add to val-019/metadata.json:")
    print(f"    input_checksum: {input_checksum}")
    print(f"    output_checksum: {output_checksum}")
    
    print("\n" + "=" * 60)
    print("  Golden vectors generated successfully")
    print("=" * 60)

if __name__ == "__main__":
    main()
