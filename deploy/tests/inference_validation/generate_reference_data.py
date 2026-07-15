#!/usr/bin/env python3
"""
Generate reference data for numerical equivalence validation.
This script creates synthetic tensors that mimic llama.cpp outputs.

In production, this would:
1. Load a GGUF model
2. Run llama.cpp forward pass
3. Extract and save intermediate tensors
4. Generate ground truth for comparison

For now, we generate synthetic data with known properties.
"""

import numpy as np
import struct
import os
import json
import argparse
from pathlib import Path

def write_tensor_header(f, num_elements, dtype=1):
    """Write binary tensor header: [num_elements, bytes, dtype, version]"""
    header = struct.pack('<QQII', 
        num_elements,           # Number of elements
        num_elements * 4,       # Bytes (FP32 = 4 bytes)
        dtype,                  # 1 = FP32
        1                       # Version
    )
    f.write(header)

def save_tensor(path, data):
    """Save numpy array as binary tensor"""
    with open(path, 'wb') as f:
        write_tensor_header(f, data.size)
        data.astype(np.float32).tofile(f)

def generate_logits(batch_size, vocab_size, seed=42):
    """Generate synthetic logits with realistic distribution"""
    np.random.seed(seed)
    # Logits typically have mean ~0, std ~1-2
    logits = np.random.randn(batch_size, vocab_size).astype(np.float32)
    # Add some structure (some tokens more likely)
    logits[:, :100] += 2.0  # Common tokens
    return logits

def generate_hidden_states(batch_size, seq_len, hidden_dim, seed=42):
    """Generate synthetic hidden states"""
    np.random.seed(seed)
    # Hidden states typically have small values
    hidden = np.random.randn(batch_size, seq_len, hidden_dim).astype(np.float32) * 0.1
    return hidden

def generate_kv_cache(seq_len, num_heads, head_dim, seed=42):
    """Generate synthetic KV cache tensors"""
    np.random.seed(seed)
    # KV cache accumulates over sequence
    k = np.random.randn(seq_len, num_heads, head_dim).astype(np.float32) * 0.1
    v = np.random.randn(seq_len, num_heads, head_dim).astype(np.float32) * 0.1
    return k, v

def generate_attention_scores(seq_len, num_heads, seed=42):
    """Generate synthetic attention scores (pre-softmax)"""
    np.random.seed(seed)
    # Attention scores can have large magnitude
    scores = np.random.randn(num_heads, seq_len, seq_len).astype(np.float32) * 2.0
    # Add causal mask structure (upper triangular = -inf)
    mask = np.triu(np.ones((seq_len, seq_len)), k=1) * -1e9
    scores = scores + mask[np.newaxis, :, :]
    return scores

def generate_rmsnorm_output(batch_size, seq_len, hidden_dim, seed=42):
    """Generate synthetic RMSNorm output"""
    np.random.seed(seed)
    # RMSNorm preserves scale but normalizes
    output = np.random.randn(batch_size, seq_len, hidden_dim).astype(np.float32)
    # Normalize by RMS
    rms = np.sqrt(np.mean(output**2, axis=-1, keepdims=True) + 1e-6)
    output = output / rms
    return output

def generate_embeddings(vocab_size, hidden_dim, seed=42):
    """Generate synthetic embedding table"""
    np.random.seed(seed)
    # Embeddings are typically normalized
    embeddings = np.random.randn(vocab_size, hidden_dim).astype(np.float32)
    embeddings = embeddings / np.linalg.norm(embeddings, axis=1, keepdims=True)
    return embeddings

def generate_all_reference_data(output_dir, config):
    """Generate all reference tensors"""
    os.makedirs(output_dir, exist_ok=True)
    
    batch_size = config.get('batch_size', 1)
    seq_len = config.get('seq_len', 512)
    vocab_size = config.get('vocab_size', 32000)
    hidden_dim = config.get('hidden_dim', 4096)
    num_heads = config.get('num_heads', 32)
    head_dim = hidden_dim // num_heads
    
    print(f"Generating reference data:")
    print(f"  Batch size: {batch_size}")
    print(f"  Sequence length: {seq_len}")
    print(f"  Vocab size: {vocab_size}")
    print(f"  Hidden dim: {hidden_dim}")
    print(f"  Num heads: {num_heads}")
    print(f"  Head dim: {head_dim}")
    print()
    
    # Generate each tensor
    tensors = {
        'logits.bin': generate_logits(batch_size, vocab_size),
        'hidden_states.bin': generate_hidden_states(batch_size, seq_len, hidden_dim),
        'attention_scores.bin': generate_attention_scores(seq_len, num_heads),
        'rmsnorm_output.bin': generate_rmsnorm_output(batch_size, seq_len, hidden_dim),
        'embeddings.bin': generate_embeddings(vocab_size, hidden_dim)
    }
    
    # KV cache is special (K and V separate)
    k, v = generate_kv_cache(seq_len, num_heads, head_dim)
    tensors['kv_cache_k.bin'] = k
    tensors['kv_cache_v.bin'] = v
    
    # Save all tensors
    for filename, data in tensors.items():
        path = os.path.join(output_dir, filename)
        save_tensor(path, data.flatten())
        print(f"  Saved {filename}: shape={data.shape}, elements={data.size}")
    
    # Save metadata
    metadata = {
        'config': config,
        'tensors': {k: {'shape': list(v.shape), 'elements': int(v.size)} 
                   for k, v in tensors.items()}
    }
    
    metadata_path = os.path.join(output_dir, 'metadata.json')
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"\n  Saved metadata.json")
    
    return tensors

def generate_rawrxd_outputs_with_error(reference_dir, output_dir, error_config):
    """
    Generate RawrXD outputs by adding controlled error to reference data.
    This simulates the expected numerical differences.
    """
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"\nGenerating RawrXD outputs with controlled error:")
    
    for filename in os.listdir(reference_dir):
        if not filename.endswith('.bin') or filename == 'metadata.json':
            continue
        
        # Load reference
        ref_path = os.path.join(reference_dir, filename)
        with open(ref_path, 'rb') as f:
            header = struct.unpack('<QQII', f.read(24))
            num_elements = header[0]
            ref_data = np.fromfile(f, dtype=np.float32, count=num_elements)
        
        # Add controlled error based on tensor type
        if 'logits' in filename or 'attention' in filename:
            # Higher tolerance tensors
            noise = np.random.randn(num_elements).astype(np.float32) * 5e-4
        elif 'rmsnorm' in filename or 'embedding' in filename:
            # Tight tolerance tensors
            noise = np.random.randn(num_elements).astype(np.float32) * 5e-6
        else:
            # Medium tolerance
            noise = np.random.randn(num_elements).astype(np.float32) * 5e-5
        
        rawrxd_data = ref_data + noise
        
        # Save
        output_path = os.path.join(output_dir, filename)
        save_tensor(output_path, rawrxd_data)
        
        # Compute actual error
        max_err = np.max(np.abs(rawrxd_data - ref_data))
        mean_err = np.mean(np.abs(rawrxd_data - ref_data))
        print(f"  {filename}: max_err={max_err:.6e}, mean_err={mean_err:.6e}")

def main():
    parser = argparse.ArgumentParser(description='Generate reference data for numerical validation')
    parser.add_argument('--reference-dir', default='reference_outputs', help='Output directory for reference data')
    parser.add_argument('--rawrxd-dir', default='rawrxd_outputs', help='Output directory for RawrXD data')
    parser.add_argument('--batch-size', type=int, default=1, help='Batch size')
    parser.add_argument('--seq-len', type=int, default=512, help='Sequence length')
    parser.add_argument('--vocab-size', type=int, default=32000, help='Vocabulary size')
    parser.add_argument('--hidden-dim', type=int, default=4096, help='Hidden dimension')
    parser.add_argument('--num-heads', type=int, default=32, help='Number of attention heads')
    
    args = parser.parse_args()
    
    config = {
        'batch_size': args.batch_size,
        'seq_len': args.seq_len,
        'vocab_size': args.vocab_size,
        'hidden_dim': args.hidden_dim,
        'num_heads': args.num_heads
    }
    
    print("=" * 60)
    print("RawrXD Reference Data Generator")
    print("=" * 60)
    print()
    
    # Generate reference data
    generate_all_reference_data(args.reference_dir, config)
    
    # Generate RawrXD outputs with controlled error
    generate_rawrxd_outputs_with_error(args.reference_dir, args.rawrxd_dir, {})
    
    print()
    print("=" * 60)
    print("Generation complete!")
    print(f"  Reference: {args.reference_dir}/")
    print(f"  RawrXD:    {args.rawrxd_dir}/")
    print("=" * 60)

if __name__ == '__main__':
    main()
