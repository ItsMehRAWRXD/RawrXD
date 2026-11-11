#!/usr/bin/env python3
"""Compare native dumps against reference captures at Layer 0, Position 1.
Handles the DifferentialRecorder header format (op_id + layer_idx + position + ndim + dims + data_size)."""
import numpy as np
import json
import os
import struct
from pathlib import Path

EVIDENCE = Path(r"F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001")
NATIVE_DIR = Path(r"F:\rawrxd")
REF_DIR = EVIDENCE / "pos1_capture_fixed"

def load_bin(path):
    if not path.exists():
        return None
    return np.fromfile(path, dtype=np.float32)

def load_with_header(path):
    """Load a DifferentialRecorder binary file, stripping the header."""
    if not path.exists():
        return None
    arr = np.fromfile(path, dtype=np.float32)
    
    # Parse header: op_id(u32), layer_idx(u32), position(u64), ndim(u32), dims..., data_size(u64), data
    # All as float32 for simplicity - just count header floats
    with open(path, 'rb') as f:
        op_id = struct.unpack('<I', f.read(4))[0]
        layer_idx = struct.unpack('<I', f.read(4))[0]
        position = struct.unpack('<Q', f.read(8))[0]
        ndim = struct.unpack('<I', f.read(4))[0]
    
    # Header size: 4 + 4 + 8 + 4 + (8*ndim) + 8 = 28 + 8*ndim bytes
    # In float32 units: (28 + 8*ndim) / 4
    header_floats = (28 + 8 * ndim) // 4
    data = arr[header_floats:]
    return data

def compare(name, native, ref):
    if native is None or ref is None:
        print(f"  {name}: missing data (native={native is not None}, ref={ref is not None})")
        return None
    if len(native) != len(ref):
        print(f"  {name}: SIZE MISMATCH native={len(native)} ref={len(ref)}")
    
    n = min(len(native), len(ref))
    native = native[:n]
    ref = ref[:n]
    
    diff = native - ref
    max_abs = np.max(np.abs(diff))
    rmse = np.sqrt(np.mean(diff * diff))
    dot = np.dot(native, ref)
    norm_n = np.linalg.norm(native)
    norm_r = np.linalg.norm(ref)
    cos = dot / (norm_n * norm_r) if norm_n > 0 and norm_r > 0 else 0.0
    
    result = {
        'name': name,
        'size': len(native),
        'native_min': float(native.min()), 'native_max': float(native.max()),
        'native_mean': float(native.mean()), 'native_std': float(native.std()),
        'ref_min': float(ref.min()), 'ref_max': float(ref.max()),
        'ref_mean': float(ref.mean()), 'ref_std': float(ref.std()),
        'cosine': float(cos), 'max_abs_diff': float(max_abs), 'rmse': float(rmse),
    }
    
    print(f"  {name} (size={len(native)}):")
    print(f"    native: min={native.min():.8f} max={native.max():.8f} mean={native.mean():.8f}")
    print(f"    ref:    min={ref.min():.8f} max={ref.max():.8f} mean={ref.mean():.8f}")
    print(f"    cos={cos:.10f} max_abs_diff={max_abs:.8f} rmse={rmse:.8f}")
    return result

print("=== Layer 0, Position 1: Native vs Reference Comparison ===\n")
results = []

# 1. Q RoPE
print("--- Q RoPE ---")
ref_q = load_with_header(REF_DIR / "rec_000006_op4_Attention_Q_RoPE_l0_p1_q_rope.bin")
native_q = load_bin(NATIVE_DIR / "layer0_pos1_q.bin")
results.append(compare("Q_RoPE", native_q, ref_q))

# 2. K_new from MlaDecompress output (first 3072 floats of 5120-element output)
print("\n--- K_new (MlaDecompress Output K portion) ---")
ref_mla_out = load_with_header(REF_DIR / "rec_000004_op2_MlaDecompress_Output_l0_p1_output.bin")
if ref_mla_out is not None:
    print(f"  Reference MlaDecompress output: {len(ref_mla_out)} floats")
    # Output layout: [16*192 K, 16*128 V] = [3072, 2048] = 5120
    ref_k_new = ref_mla_out[:16*192]
    ref_v_new = ref_mla_out[16*192:16*192 + 16*128]
    native_k_new = load_bin(NATIVE_DIR / "layer0_pos1_k_new.bin")
    results.append(compare("K_new", native_k_new, ref_k_new))
    
    # Also check V (native doesn't dump V separately, but let's see ref stats)
    print(f"\n  Reference V_new: min={ref_v_new.min():.6f} max={ref_v_new.max():.6f} mean={ref_v_new.mean():.6f}")

# 3. K_cached_after_write vs K_new
print("\n--- K Write Verification ---")
native_k_new = load_bin(NATIVE_DIR / "layer0_pos1_k_new.bin")
native_k_cached = load_bin(NATIVE_DIR / "layer0_pos1_k_cached_after_write.bin")
if native_k_new is not None and native_k_cached is not None and ref_k_new is not None:
    # Compare K_new to K_cached - difference is RoPE on the k_rope portion
    # k_pe is positions [192, 256] per head in K_new
    diff_k = native_k_new - native_k_cached
    print(f"  K_new vs K_cached: max_abs_diff={np.max(np.abs(diff_k)):.6f} RMSE={np.sqrt(np.mean(diff_k**2)):.6f}")
    # The k_nope portion should match exactly
    k_nope_new = native_k_new[:16*128].reshape(16, 128)
    k_nope_cached = native_k_cached[:16*128].reshape(16, 128)
    diff_nope = k_nope_new - k_nope_cached
    print(f"  K_nope (128/head) max_abs_diff={np.max(np.abs(diff_nope)):.8f}")
    
    # Compare K_new to reference K_new
    print(f"\n  K_new vs Reference: max_abs_diff={np.max(np.abs(native_k_new - ref_k_new)):.8f}")
    # Per-head K_nope comparison
    for h in range(2):  # Check first 2 heads
        head_new = native_k_new[h*192:(h+1)*192]
        head_ref = ref_k_new[h*192:(h+1)*192]
        head_diff = head_new - head_ref
        print(f"  Head {h}: max_abs_diff={np.max(np.abs(head_diff)):.8f} cos={np.dot(head_new, head_ref)/(np.linalg.norm(head_new)*np.linalg.norm(head_ref)):.8f}")

# 4. Attention Scores
print("\n--- Attention Scores ---")
ref_scores = load_with_header(REF_DIR / "rec_000007_op4_Attention_Scores_l0_p1_scaled_scores.bin")
if ref_scores is not None:
    print(f"  Reference scores: {len(ref_scores)} elements (expected 32 = 16 heads × 2 positions)")
    print(f"  ref: min={ref_scores.min():.8f} max={ref_scores.max():.8f} mean={ref_scores.mean():.8f} std={ref_scores.std():.8f}")
    print(f"  ref shape hint: {ref_scores[:5]}")
    # Reshape to 16x2 if correct size
    if len(ref_scores) == 32:
        scores_16x2 = ref_scores.reshape(16, 2)
        for h in range(16):
            print(f"  Head {h}: score[0]={scores_16x2[h,0]:.6f} score[1]={scores_16x2[h,1]:.6f}")

# 5. Softmax Weights
print("\n--- Softmax Weights ---")
ref_weights = load_with_header(REF_DIR / "rec_000008_op4_Attention_Weights_l0_p1_softmax.bin")
native_weights = load_bin(NATIVE_DIR / "layer0_pos1_attn_weights.bin")
if ref_weights is not None and native_weights is not None:
    if len(ref_weights) == len(native_weights):
        results.append(compare("Softmax", native_weights, ref_weights))
    else:
        print(f"  Size mismatch: native={len(native_weights)} ref={len(ref_weights)}")
        print(f"  ref: min={ref_weights.min():.8f} max={ref_weights.max():.8f} sum={ref_weights.sum():.8f}")
        print(f"  native: min={native_weights.min():.8f} max={native_weights.max():.8f} sum={native_weights.sum():.8f}")
        ref_16x2 = ref_weights.reshape(16, 2)
        native_16x2 = native_weights.reshape(16, 2)
        for h in range(16):
            w_diff = native_16x2[h] - ref_16x2[h]
            print(f"  Head {h}: native=[{native_16x2[h,0]:.6f}, {native_16x2[h,1]:.6f}] ref=[{ref_16x2[h,0]:.6f}, {ref_16x2[h,1]:.6f}] diff_max={np.max(np.abs(w_diff)):.8f}")

# 6. Attention Output
print("\n--- Attention Output ---")
ref_output = load_with_header(REF_DIR / "rec_000009_op4_Attention_Output_l0_p1_output.bin")
native_output = load_bin(NATIVE_DIR / "layer0_pos1_attn_output.bin")
results.append(compare("Attention_Output", native_output, ref_output))

# 7. Check the kv_prefix reference capture
print("\n--- KV Cache Prefix ---")
ref_prefix = load_with_header(REF_DIR / "rec_000003_op2_MLA_CacheKV_Prefix_l0_p1_kv_prefix.bin")
if ref_prefix is not None:
    print(f"  KV prefix: {len(ref_prefix)} floats")
    print(f"  min={ref_prefix.min():.6f} max={ref_prefix.max():.6f} mean={ref_prefix.mean():.6f}")

print("\n=== KEY INSIGHTS ===")
print("1. K_new vs reference check will isolate projection/RoPE bugs")
print("2. K_cached_after_write vs K_new will isolate cache write bugs")
print("3. Attention scores comparison will isolate scaling issues")
print("4. Softmax comparison will isolate normalization issues")
print("5. Attention output comparison will isolate V accumulation bugs")

# Save results
with open(NATIVE_DIR / "evidence\l0p1_native_vs_ref.json", 'w') as f:
    json.dump([v for v in results if v is not None], f, indent=2, default=str)
print("\nResults saved to L0P1 comparison")

