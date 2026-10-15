#!/usr/bin/env python3
"""
Apply final RMSNorm to Deep2's model body output and compare with reference hidden state.
"""
import os
import struct
import numpy as np
import gguf

D2 = r"F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone"
REF = r"F:\rawrxd\evidence\deep2_gate_a\ref_head_extended"
MODEL = r"F:\rawrxd\llama3.2-3b-Q2_K.gguf"

def load_bin(path, dtype='<f4'):
    with open(path, 'rb') as f:
        data = f.read()
    return np.frombuffer(data, dtype=dtype).astype(np.float64)

def find_tensor_file(pos, blk, pc, name):
    def sanitize(s):
        out = ""
        for c in s:
            if c.isalnum() or c in '-_.':
                out += c
            else:
                out += '_'
        return out
    clean_name = sanitize(name)
    blk_str = str(blk) if blk >= 0 else "999"
    path = os.path.join(D2, f"d2_pos{pos}_blk{blk_str}_pc{pc}_{clean_name}.bin")
    if os.path.exists(path):
        return path
    return None

def rmsnorm(x, weight, eps=1e-5):
    """Apply RMSNorm: output = (x / rms(x)) * weight"""
    ss = np.sum(x * x)
    rms = np.sqrt(ss / len(x) + eps)
    return x / rms * weight

# Load final norm weight from GGUF
reader = gguf.GGUFReader(MODEL)
final_norm_weight = None
for tensor in reader.tensors:
    if tensor.name == 'output_norm.weight':
        # Type 0 = F32
        data = tensor.data
        if tensor.tensor_type == 0:
            final_norm_weight = data.astype(np.float64)
        break

if final_norm_weight is None:
    print("ERROR: Could not find output_norm.weight")
    exit(1)

print(f"Final norm weight: {final_norm_weight.shape}, range=[{np.min(final_norm_weight):.4f}, {np.max(final_norm_weight):.4f}]")

# Load reference hidden states
ref_h9 = load_bin(os.path.join(REF, "ref_hidden_pos0.bin"))
ref_h10 = load_bin(os.path.join(REF, "ref_hidden_pos1.bin"))

# Load Deep2 model body output (out_norm from trace, which is pre-final-norm)
for pos, ref_h, ref_name in [(9, ref_h9, "pos9"), (10, ref_h10, "pos10")]:
    d2_body = load_bin(find_tensor_file(pos, -1, 393, 'out_norm'))
    
    print(f"\n=== {ref_name} ===")
    print(f"Deep2 body output: {d2_body.shape}")
    print(f"Ref hidden (post-final-norm): {ref_h.shape}")
    
    # Apply final RMSNorm to Deep2 body output
    d2_post_norm = rmsnorm(d2_body, final_norm_weight)
    
    # Compare
    diff = ref_h - d2_post_norm
    cos = np.dot(ref_h, d2_post_norm) / (np.linalg.norm(ref_h) * np.linalg.norm(d2_post_norm))
    maxabs = np.max(np.abs(diff))
    rmse = np.sqrt(np.mean(diff**2))
    print(f"Deep2 post-final-norm vs Ref hidden: cos={cos:.6f}, maxabs={maxabs:.6f}, rmse={rmse:.6f}")
    
    # Also compare Deep2 body output vs llama.cpp body output (we don't have this)
    # But we can check if the final norm is the main difference
    print(f"Deep2 body vs Ref hidden (pre-norm): cos={np.dot(d2_body, ref_h)/(np.linalg.norm(d2_body)*np.linalg.norm(ref_h)):.6f}")

# Also compute llama.cpp body output by inverting the final norm on ref hidden
# ref_h = rmsnorm(llama_body, weight) => llama_body = ref_h * rms(llama_body) / weight
# But we don't know rms(llama_body). However, we can compute the scaling:
# ref_h[i] = llama_body[i] / rms * weight[i] => llama_body[i] = ref_h[i] * rms / weight[i]
# The RMS is the same for all elements, so llama_body is ref_h scaled by weight.

# Let's check the ratio
print("\n=== Weight analysis ===")
print(f"Final norm weight stats: mean={np.mean(final_norm_weight):.4f}, std={np.std(final_norm_weight):.4f}")
print(f"Ref h9 stats: mean={np.mean(ref_h9):.4f}, std={np.std(ref_h9):.4f}")
print(f"D2 body9 stats: mean={np.mean(d2_body):.4f}, std={np.std(d2_body):.4f}")

# The RMSNorm formula: out = x * weight / rms(x)
# So x = out * rms(x) / weight
# rms(x) = sqrt(sum(x^2)/dim)
# This is a fixed point equation. But we can check if x is roughly proportional to out/weight
# If the weight is nearly constant, then x ≈ out * constant
weight_cv = np.std(final_norm_weight) / np.mean(final_norm_weight)
print(f"Weight coefficient of variation: {weight_cv:.4f}")

# If weight is constant, RMSNorm just scales by constant factor
# Let's check if the difference is just a scaling factor
scale9 = np.linalg.norm(ref_h9) / np.linalg.norm(d2_body)
scale10 = np.linalg.norm(ref_h10) / np.linalg.norm(d2_body)
print(f"Scale factor pos9: {scale9:.4f}")
print(f"Scale factor pos10: {scale10:.4f}")

# Apply inverse RMSNorm to ref to get llama body output estimate
# If ref = body / rms * w, then body = ref * rms / w
# rms = sqrt(mean(body^2)) = sqrt(mean((ref * rms / w)^2)) = rms * sqrt(mean((ref/w)^2))
# So 1 = sqrt(mean((ref/w)^2)) => mean((ref/w)^2) = 1
# Check this:
for pos, ref_h in [(9, ref_h9), (10, ref_h10)]:
    ratio = ref_h / final_norm_weight
    mean_sq = np.mean(ratio * ratio)
    print(f"Pos{pos}: mean((ref/weight)^2) = {mean_sq:.4f} (should be ~1 if ref is post-RMSNorm)")