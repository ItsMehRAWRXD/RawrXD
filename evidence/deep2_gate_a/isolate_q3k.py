#!/usr/bin/env python3
"""
Isolate Q3_K vec_dot issue by comparing Deep2 scalar GEMV vs llama.cpp reference.
"""
import os
import subprocess
import numpy as np
import gguf

# Load a Q3_K weight tensor and test vector
MODEL = r"F:\rawrxd\llama3.2-3b-Q2_K.gguf"
reader = gguf.GGUFReader(MODEL)

# Find blk.0.attn_q.weight (Q3_K)
q_weight = None
for tensor in reader.tensors:
    if tensor.name == 'blk.0.attn_q.weight':
        q_weight = tensor
        break

if q_weight is None:
    print("Could not find blk.0.attn_q.weight")
    exit(1)

print(f"Q weight: {q_weight.name}, shape={q_weight.shape}, type={q_weight.tensor_type}")

# Dequantize using llama.cpp reference
# We'll use the reference dumper to get the correct output

# Create a simple test input
np.random.seed(42)
test_input = np.random.randn(3072).astype(np.float32)

# Save test input
test_input.tofile(r"F:\rawrxd\evidence\deep2_gate_a\test_input.bin")

# Use llama.cpp to compute reference GEMV
# We need to call the quantized GEMV directly
# For now, let's check the Deep2 CPU GEMV output

# The trace files have the Deep2 GEMV output for Q projection
# Let's load and check

D2 = r"F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone"
REF = r"F:\rawrxd\evidence\deep2_gate_a\ref_intermediate_full"

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

# Load Deep2 Q projection output for pos 10
trace10_path = os.path.join(D2, "d2_trace_pos10.txt")
trace10_map = {}
with open(trace10_path, 'r') as f:
    for line in f:
        if line.startswith('blk='):
            parts = line.strip().split()
            blk = int(parts[0].split('=')[1])
            pc = int(parts[1].split('=')[1])
            op = int(parts[2].split('=')[1])
            name = parts[3].split('=')[1]
            size = int(parts[4].split('=')[1])
            trace10_map[(blk, name)] = pc

pc_q = trace10_map.get((0, 'q'))
print(f"Layer 0 Q projection pc={pc_q}")

d2_q_path = find_tensor_file(10, 0, pc_q, 'q')
if d2_q_path:
    d2_q = load_bin(d2_q_path)
    print(f"Deep2 Q shape: {d2_q.shape}")
    print(f"Deep2 Q stats: mean={np.mean(d2_q):.4f}, std={np.std(d2_q):.4f}, range=[{np.min(d2_q):.4f}, {np.max(d2_q):.4f}]")

# Load reference Q projection
ref_q_path = os.path.join(REF, "ref_pos10_layer0_q_layer0.bin")
if os.path.exists(ref_q_path):
    ref_q = load_bin(ref_q_path)
    print(f"Ref Q shape: {ref_q.shape}")
    print(f"Ref Q stats: mean={np.mean(ref_q):.4f}, std={np.std(ref_q):.4f}, range=[{np.min(ref_q):.4f}, {np.max(ref_q):.4f}]")
    
    diff = ref_q - d2_q
    cos = np.dot(ref_q, d2_q) / (np.linalg.norm(ref_q) * np.linalg.norm(d2_q))
    maxabs = np.max(np.abs(diff))
    rmse = np.sqrt(np.mean(diff**2))
    print(f"Diff: cos={cos:.6f}, maxabs={maxabs:.6f}, rmse={rmse:.6f}")
    
    # Check first few elements
    print("\nFirst 20 elements:")
    for i in range(20):
        print(f"  [{i:3d}] Ref: {ref_q[i]:10.6f}  D2: {d2_q[i]:10.6f}  Diff: {diff[i]:10.6f}")