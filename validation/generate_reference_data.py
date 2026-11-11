#!/usr/bin/env python3
"""
Generate Reference Data from llama.cpp
Creates golden test data for layer-by-layer validation
"""

import subprocess
import struct
import json
import numpy as np
from pathlib import Path

def run_llama_cpp_layer(model_path, prompt, layer_type, n_tokens=10):
    """
    Run llama.cpp with hooks to extract intermediate layer outputs
    This would require a modified llama.cpp that dumps layer outputs
    """
    
    # Example: Run llama.cpp with debug flags to extract embeddings
    cmd = [
        "./llama.cpp/build/bin/llama-cli",
        "-m", model_path,
        "-p", prompt,
        "-n", str(n_tokens),
        "--temp", "0.0",
        "--seed", "42",
        "--dump-tensors", f"{layer_type}_ref.bin"  # Hypothetical flag
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0

def generate_embedding_reference(model_path, output_dir):
    """Generate reference embedding outputs"""
    print("Generating embedding reference data...")
    
    test_prompts = [
        "The capital of France is",
        "def hello_world():",
        "Once upon a time",
        "#include <stdio.h>",
        "The quick brown fox"
    ]
    
    for i, prompt in enumerate(test_prompts):
        output_file = output_dir / f"embedding_prompt{i}.bin"
        
        # This would call modified llama.cpp
        # For now, placeholder structure
        ref_data = {
            "prompt": prompt,
            "tokens": [],  # Would be filled from llama.cpp
            "embeddings": [],  # Would be filled from llama.cpp
            "shape": [len(prompt), 4096]  # [n_tokens, hidden_dim]
        }
        
        with open(output_file, 'wb') as f:
            # Write header
            f.write(b'LLAMA_REFv1')  # Magic
            f.write(struct.pack('I', ref_data['shape'][0]))
            f.write(struct.pack('I', ref_data['shape'][1]))
            
            # Write embeddings (placeholder)
            # In reality, this would come from llama.cpp
            embeddings = np.random.randn(ref_data['shape'][0], ref_data['shape'][1]).astype(np.float32)
            f.write(embeddings.tobytes())
    
    print(f"  Generated {len(test_prompts)} embedding reference files")

def generate_rmsnorm_reference(model_path, output_dir):
    """Generate reference RMSNorm outputs"""
    print("Generating RMSNorm reference data...")
    
    # Test inputs at different scales
    test_inputs = [
        np.ones(4096, dtype=np.float32),
        np.random.randn(4096).astype(np.float32),
        np.full(4096, 0.5, dtype=np.float32),
    ]
    
    for i, input_data in enumerate(test_inputs):
        output_file = output_dir / f"rmsnorm_input{i}.bin"
        
        # Reference RMSNorm calculation
        epsilon = 1e-6
        mean_sq = np.mean(input_data ** 2)
        rms = np.sqrt(mean_sq + epsilon)
        reference_output = input_data / rms
        
        with open(output_file, 'wb') as f:
            f.write(b'RMSNv1')  # Magic
            f.write(struct.pack('I', 4096))
            f.write(struct.pack('f', epsilon))
            f.write(input_data.tobytes())
            f.write(reference_output.tobytes())
    
    print(f"  Generated {len(test_inputs)} RMSNorm reference files")

def generate_rope_reference(output_dir):
    """Generate reference RoPE outputs"""
    print("Generating RoPE reference data...")
    
    head_dim = 128
    max_pos = 8192
    theta = 10000.0
    
    # Precompute RoPE frequencies
    freqs = 1.0 / (theta ** (np.arange(0, head_dim, 2).astype(np.float32) / head_dim))
    
    for pos in [0, 1, 10, 100, 1000]:
        output_file = output_dir / f"rope_pos{pos}.bin"
        
        # Create test Q and K vectors
        q = np.random.randn(head_dim).astype(np.float32)
        k = np.random.randn(head_dim).astype(np.float32)
        
        # Apply RoPE (reference implementation)
        angles = pos * freqs
        cos_angles = np.cos(angles)
        sin_angles = np.sin(angles)
        
        q_out = q.copy()
        k_out = k.copy()
        
        # Rotate pairs of dimensions
        for i in range(0, head_dim, 2):
            if i + 1 < head_dim:
                q_out[i] = q[i] * cos_angles[i//2] - q[i+1] * sin_angles[i//2]
                q_out[i+1] = q[i] * sin_angles[i//2] + q[i+1] * cos_angles[i//2]
                k_out[i] = k[i] * cos_angles[i//2] - k[i+1] * sin_angles[i//2]
                k_out[i+1] = k[i] * sin_angles[i//2] + k[i+1] * cos_angles[i//2]
        
        with open(output_file, 'wb') as f:
            f.write(b'ROPEv1')
            f.write(struct.pack('I', head_dim))
            f.write(struct.pack('I', pos))
            f.write(struct.pack('f', theta))
            f.write(q.tobytes())
            f.write(k.tobytes())
            f.write(q_out.tobytes())
            f.write(k_out.tobytes())
    
    print(f"  Generated RoPE reference files for positions [0, 1, 10, 100, 1000]")

def generate_attention_reference(output_dir):
    """Generate reference attention outputs"""
    print("Generating attention reference data...")
    
    # Test configurations
    configs = [
        {"n_heads": 32, "head_dim": 128, "n_tokens": 1, "n_kv": 10},
        {"n_heads": 32, "head_dim": 128, "n_tokens": 5, "n_kv": 15},
    ]
    
    for i, cfg in enumerate(configs):
        output_file = output_dir / f"attention_config{i}.bin"
        
        # Generate random Q, K, V
        q = np.random.randn(cfg["n_heads"], cfg["n_tokens"], cfg["head_dim"]).astype(np.float32)
        k = np.random.randn(cfg["n_heads"], cfg["n_kv"], cfg["head_dim"]).astype(np.float32)
        v = np.random.randn(cfg["n_heads"], cfg["n_kv"], cfg["head_dim"]).astype(np.float32)
        
        # Reference attention calculation
        scale = 1.0 / np.sqrt(cfg["head_dim"])
        
        # Q @ K^T
        scores = np.matmul(q, k.transpose(0, 2, 1)) * scale
        
        # Softmax
        exp_scores = np.exp(scores - np.max(scores, axis=-1, keepdims=True))
        attn_weights = exp_scores / np.sum(exp_scores, axis=-1, keepdims=True)
        
        # Attention @ V
        output = np.matmul(attn_weights, v)
        
        with open(output_file, 'wb') as f:
            f.write(b'ATTNv1')
            f.write(struct.pack('I', cfg["n_heads"]))
            f.write(struct.pack('I', cfg["head_dim"]))
            f.write(struct.pack('I', cfg["n_tokens"]))
            f.write(struct.pack('I', cfg["n_kv"]))
            f.write(q.tobytes())
            f.write(k.tobytes())
            f.write(v.tobytes())
            f.write(output.tobytes())
    
    print(f"  Generated {len(configs)} attention reference files")

def generate_quantization_reference(output_dir):
    """Generate reference quantization/dequantization data"""
    print("Generating quantization reference data...")
    
    # Test Q4_0
    print("  Q4_0...")
    n = 128  # Must be multiple of 32 for Q4_0
    
    # Random weights
    weights = np.random.randn(n).astype(np.float32)
    
    # Find max absolute value
    max_abs = np.max(np.abs(weights))
    scale = max_abs / 7.0  # 7 = max value for 4-bit signed
    
    # Quantize
    quantized = np.round(weights / scale).astype(np.int8)
    quantized = np.clip(quantized, -8, 7)
    
    # Pack into bytes (2 values per byte)
    packed = np.zeros(n // 2, dtype=np.uint8)
    for i in range(0, n, 2):
        packed[i//2] = (quantized[i] & 0xF) | ((quantized[i+1] & 0xF) << 4)
    
    # Dequantize
    dequantized = np.zeros(n, dtype=np.float32)
    for i in range(0, n, 2):
        dequantized[i] = (packed[i//2] & 0xF) * scale
        dequantized[i+1] = ((packed[i//2] >> 4) & 0xF) * scale
    
    output_file = output_dir / "q4_0_reference.bin"
    with open(output_file, 'wb') as f:
        f.write(b'Q4_0v1')
        f.write(struct.pack('I', n))
        f.write(struct.pack('f', scale))
        f.write(packed.tobytes())
        f.write(weights.tobytes())  # Original
        f.write(dequantized.tobytes())  # Dequantized
    
    print(f"    Generated Q4_0 reference (scale={scale:.6f})")

def main():
    """Generate all reference data"""
    
    output_dir = Path("d:/rawrxd/validation/reference_data")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print("=" * 60)
    print("GENERATING REFERENCE DATA")
    print("=" * 60)
    print(f"Output directory: {output_dir}")
    print()
    
    # Generate reference data for each component
    generate_embedding_reference(None, output_dir)
    generate_rmsnorm_reference(None, output_dir)
    generate_rope_reference(output_dir)
    generate_attention_reference(output_dir)
    generate_quantization_reference(output_dir)
    
    print()
    print("=" * 60)
    print("REFERENCE DATA GENERATION COMPLETE")
    print("=" * 60)
    print()
    print("Note: These are synthetic reference data.")
    print("For true validation, replace with actual llama.cpp outputs.")
    print()
    print("Next steps:")
    print("1. Modify llama.cpp to dump layer outputs")
    print("2. Run llama.cpp on test prompts")
    print("3. Replace synthetic data with real llama.cpp outputs")
    print("4. Run RawrXD validation tests")

if __name__ == "__main__":
    main()
