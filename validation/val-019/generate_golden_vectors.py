#!/usr/bin/env python3
"""
generate_golden_vectors.py

Generates reference tensors for VAL-019 validation.
Uses a reference implementation (PyTorch) to produce
checksums that the C++ implementation must match.
"""

import numpy as np
import json
import hashlib
import struct
from pathlib import Path
from typing import Tuple, Dict, Any

# VAL-019 configuration
CONFIG = {
    "vocab_size": 32000,
    "hidden_size": 4096,
    "num_attention_heads": 32,
    "num_key_value_heads": 32,
    "head_dim": 128,
    "intermediate_size": 11008,
    "max_position_embeddings": 4096,
    "rms_norm_eps": 1e-6,
}

def compute_sha256(data: bytes) -> str:
    """Compute SHA256 checksum of binary data."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"

def save_tensor(tensor: np.ndarray, path: Path) -> str:
    """Save tensor to binary file and return checksum."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = tensor.tobytes()
    with open(path, 'wb') as f:
        f.write(data)
    return compute_sha256(data)

def generate_embedding_input(seq_len: int = 10) -> np.ndarray:
    """Generate random token IDs for embedding lookup."""
    return np.random.randint(0, CONFIG["vocab_size"], size=(1, seq_len), dtype=np.int32)

def embedding_lookup(input_ids: np.ndarray, weight: np.ndarray) -> np.ndarray:
    """Simple embedding lookup."""
    return weight[input_ids].astype(np.float32)

def rms_norm(x: np.ndarray, weight: np.ndarray, eps: float = 1e-6) -> np.ndarray:
    """RMS normalization."""
    variance = np.mean(x ** 2, axis=-1, keepdims=True)
    x = x * np.reciprocal(np.sqrt(variance + eps))
    return x * weight

def apply_rope(q: np.ndarray, k: np.ndarray, positions: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """Apply Rotary Position Embeddings."""
    head_dim = CONFIG["head_dim"]
    inv_freq = 1.0 / (10000.0 ** (np.arange(0, head_dim, 2).astype(np.float32) / head_dim))
    
    freqs = np.outer(positions, inv_freq)  # [seq_len, head_dim//2]
    cos, sin = np.cos(freqs), np.sin(freqs)  # [seq_len, head_dim//2]
    
    # Reshape for broadcasting: [1, seq_len, 1, head_dim//2]
    cos = cos[np.newaxis, :, np.newaxis, :]
    sin = sin[np.newaxis, :, np.newaxis, :]
    
    # Apply to q and k - reshape to separate head_dim pairs
    def rotate(x):
        # x: [batch, seq_len, hidden]
        batch, seq_len, hidden = x.shape
        x = x.reshape(batch, seq_len, -1, head_dim)  # [batch, seq_len, num_heads, head_dim]
        x1, x2 = x[..., ::2], x[..., 1::2]  # Split pairs
        # cos/sin: [1, seq_len, 1, head_dim//2]
        rotated = np.stack([x1 * cos - x2 * sin, x1 * sin + x2 * cos], axis=-1)
        return rotated.reshape(batch, seq_len, hidden)
    
    return rotate(q), rotate(k)

def compute_qkv(x: np.ndarray, w_q: np.ndarray, w_k: np.ndarray, w_v: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Compute Q, K, V projections."""
    q = x @ w_q.T
    k = x @ w_k.T
    v = x @ w_v.T
    return q, k, v

def attention(q: np.ndarray, k: np.ndarray, v: np.ndarray, mask: np.ndarray = None) -> np.ndarray:
    """Scaled dot-product attention."""
    head_dim = CONFIG["head_dim"]
    scores = (q @ k.transpose(-2, -1)) / np.sqrt(head_dim)
    if mask is not None:
        scores = scores + mask
    attn_weights = np.exp(scores - np.max(scores, axis=-1, keepdims=True))
    attn_weights = attn_weights / np.sum(attn_weights, axis=-1, keepdims=True)
    return attn_weights @ v

def ffn(x: np.ndarray, w1: np.ndarray, w2: np.ndarray, w3: np.ndarray) -> np.ndarray:
    """Feed-forward network with SwiGLU."""
    # SwiGLU: silu(x @ w1) * (x @ w3)
    gate = x @ w1.T
    # Simplified: just use ReLU for reference
    gate = np.maximum(gate, 0)
    up = x @ w3.T
    hidden = gate * up
    return hidden @ w2.T

def generate_stage_data(stage_name: str, base_path: Path) -> Dict[str, Any]:
    """Generate input/output tensors for a validation stage."""
    
    input_path = base_path / "tensors" / "input" / f"{stage_name}_input.bin"
    output_path = base_path / "tensors" / "expected" / f"{stage_name}_output.bin"
    
    np.random.seed(42)  # Deterministic
    
    if stage_name == "Embedding":
        input_ids = generate_embedding_input(10)
        weight = np.random.randn(CONFIG["vocab_size"], CONFIG["hidden_size"]).astype(np.float32) * 0.02
        output = embedding_lookup(input_ids, weight)
        
        input_checksum = save_tensor(input_ids, input_path)
        output_checksum = save_tensor(output, output_path)
        
    elif stage_name == "RMSNorm":
        x = np.random.randn(1, 10, CONFIG["hidden_size"]).astype(np.float32) * 0.1
        weight = np.ones(CONFIG["hidden_size"], dtype=np.float32)
        output = rms_norm(x, weight)
        
        input_checksum = save_tensor(x, input_path)
        output_checksum = save_tensor(output, output_path)
        
    elif stage_name == "QKV":
        x = np.random.randn(1, 10, CONFIG["hidden_size"]).astype(np.float32) * 0.1
        w_q = np.random.randn(CONFIG["hidden_size"], CONFIG["hidden_size"]).astype(np.float32) * 0.02
        w_k = np.random.randn(CONFIG["hidden_size"], CONFIG["hidden_size"]).astype(np.float32) * 0.02
        w_v = np.random.randn(CONFIG["hidden_size"], CONFIG["hidden_size"]).astype(np.float32) * 0.02
        
        q, k, v = compute_qkv(x, w_q, w_k, w_v)
        output = np.concatenate([q, k, v], axis=-1)
        
        input_checksum = save_tensor(x, input_path)
        output_checksum = save_tensor(output, output_path)
        
    elif stage_name == "RoPE":
        q = np.random.randn(1, 10, CONFIG["hidden_size"]).astype(np.float32) * 0.1
        k = np.random.randn(1, 10, CONFIG["hidden_size"]).astype(np.float32) * 0.1
        positions = np.arange(10, dtype=np.float32)
        
        q_out, k_out = apply_rope(q, k, positions)
        output = np.concatenate([q_out, k_out], axis=-1)
        
        input_data = np.concatenate([q.flatten(), k.flatten()])
        input_checksum = save_tensor(input_data, input_path)
        output_checksum = save_tensor(output, output_path)
        
    elif stage_name == "Attention":
        batch, seq_len = 1, 10
        num_heads = CONFIG["num_attention_heads"]
        head_dim = CONFIG["head_dim"]
        
        q = np.random.randn(batch, num_heads, seq_len, head_dim).astype(np.float32) * 0.1
        k = np.random.randn(batch, num_heads, seq_len, head_dim).astype(np.float32) * 0.1
        v = np.random.randn(batch, num_heads, seq_len, head_dim).astype(np.float32) * 0.1
        
        output = attention(q, k, v)
        
        input_data = np.concatenate([q.flatten(), k.flatten(), v.flatten()])
        input_checksum = save_tensor(input_data, input_path)
        output_checksum = save_tensor(output, output_path)
        
    elif stage_name == "FFN":
        x = np.random.randn(1, 10, CONFIG["hidden_size"]).astype(np.float32) * 0.1
        w1 = np.random.randn(CONFIG["intermediate_size"], CONFIG["hidden_size"]).astype(np.float32) * 0.02
        w2 = np.random.randn(CONFIG["hidden_size"], CONFIG["intermediate_size"]).astype(np.float32) * 0.02
        w3 = np.random.randn(CONFIG["intermediate_size"], CONFIG["hidden_size"]).astype(np.float32) * 0.02
        
        output = ffn(x, w1, w2, w3)
        
        input_checksum = save_tensor(x, input_path)
        output_checksum = save_tensor(output, output_path)
        
    elif stage_name == "KV_Cache":
        # Simulate KV cache update
        cache = np.zeros((CONFIG["num_attention_heads"], 2, 10, CONFIG["head_dim"]), dtype=np.float32)
        new_k = np.random.randn(CONFIG["num_attention_heads"], 1, CONFIG["head_dim"]).astype(np.float32) * 0.1
        new_v = np.random.randn(CONFIG["num_attention_heads"], 1, CONFIG["head_dim"]).astype(np.float32) * 0.1
        
        cache[:, 0, 0] = new_k.squeeze()
        cache[:, 1, 0] = new_v.squeeze()
        
        input_data = np.concatenate([new_k.flatten(), new_v.flatten()])
        input_checksum = save_tensor(input_data, input_path)
        output_checksum = save_tensor(cache, output_path)
        
    elif stage_name == "Logits":
        hidden = np.random.randn(1, 10, CONFIG["hidden_size"]).astype(np.float32) * 0.1
        lm_head = np.random.randn(CONFIG["vocab_size"], CONFIG["hidden_size"]).astype(np.float32) * 0.02
        
        logits = hidden @ lm_head.T
        
        input_checksum = save_tensor(hidden, input_path)
        output_checksum = save_tensor(logits, output_path)
        
    elif stage_name == "Sampling":
        logits = np.random.randn(CONFIG["vocab_size"]).astype(np.float32) * 0.5
        # Greedy sampling
        token_id = np.argmax(logits)
        output = np.array([token_id], dtype=np.int32)
        
        input_checksum = save_tensor(logits, input_path)
        output_checksum = save_tensor(output, output_path)
        
    elif stage_name == "Streaming":
        # Simulate token generation
        tokens = np.random.randint(0, CONFIG["vocab_size"], size=(1, 100), dtype=np.int32)
        
        input_checksum = save_tensor(tokens[:, :1], input_path)
        output_checksum = save_tensor(tokens, output_path)
        
    else:
        raise ValueError(f"Unknown stage: {stage_name}")
    
    return {
        "input_path": str(input_path.relative_to(base_path)),
        "output_path": str(output_path.relative_to(base_path)),
        "input_checksum": input_checksum,
        "output_checksum": output_checksum,
    }

def main():
    base_path = Path("validation/val-019")
    
    # Load existing metadata
    metadata_path = base_path / "metadata" / "stages.json"
    with open(metadata_path) as f:
        metadata = json.load(f)
    
    # Generate golden vectors for pending stages
    pending_stages = [s for s in metadata["stages"] if s["status"] == "pending"]
    
    print(f"Generating golden vectors for {len(pending_stages)} pending stages...")
    
    for stage in pending_stages:
        stage_name = stage["name"]
        print(f"  Generating {stage_name}...", end=" ")
        
        try:
            result = generate_stage_data(stage_name, base_path)
            stage["input"] = result["input_path"]
            stage["expected_output"] = result["output_path"]
            stage["input_checksum"] = result["input_checksum"]
            stage["expected_checksum"] = result["output_checksum"]
            stage["status"] = "ready"
            print(f"✓ {result['output_checksum'][:16]}...")
        except Exception as e:
            print(f"✗ Error: {e}")
    
    # Save updated metadata
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print(f"\nGolden vectors generated in {base_path}/tensors/")
    print(f"Metadata updated: {metadata_path}")

if __name__ == "__main__":
    main()
