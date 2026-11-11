#!/usr/bin/env python3
"""
Test which reference Q stage matches Deep2's Q projection output.
"""
import os
import numpy as np

D2 = r"F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone"
REF = r"F:\rawrxd\evidence\deep2_gate_a\ref_intermediate_v2"

def load_bin(path, dtype='<f4'):
    with open(path, 'rb') as f:
        return np.frombuffer(f.read(), dtype=dtype).astype(np.float64)

def find_tensor_file(pos, blk, pc, name):
    def sanitize(s):
        return ''.join(c if (c.isalnum() or c in '-_.') else '_' for c in name)
    path = os.path.join(D2, f"d2_pos{pos}_blk{blk}_pc{pc}_{sanitize(name)}.bin")
    return path if os.path.exists(path) else None

# Get Deep2 Q projection at pos 10, layer 0
trace10 = {}
with open(os.path.join(D2, "d2_trace_pos10.txt")) as f:
    for line in f:
        if line.startswith('blk='):
            p = line.strip().split()
            trace10[(int(p[0].split('=')[1]), p[3].split('=')[1])] = int(p[1].split('=')[1])

d2_q = load_bin(find_tensor_file(10, 0, trace10[(0,'q')], 'q'))
print(f"Deep2 Q: {d2_q.shape}")

# Compare against all reference stages
for stage in range(6):
    fname = "ref_pos10_layer0_q_layer0.bin" if stage == 0 else f"ref_pos10_layer0_q_layer0_stage{stage}.bin"
    ref = load_bin(os.path.join(REF, fname))
    cos = np.dot(d2_q, ref)/(np.linalg.norm(d2_q)*np.linalg.norm(ref))
    diff = d2_q - ref
    maxabs = np.max(np.abs(diff))
    rmse = np.sqrt(np.mean(diff**2))
    print(f"Stage {stage}: cos={cos:.6f}, maxabs={maxabs:.6f}, rmse={rmse:.6f}")

# Also try stage0 with Llama head-pair permutation (GGUF undo_permute)
print("\n=== Testing Llama head-pair permutation on stage0 ===")
ref0 = load_bin(os.path.join(REF, "ref_pos10_layer0_q_layer0.bin"))

# The GGUF conversion permutes Q weights. The standard Llama permute:
# view as (n_heads, head_dim), then swap first half with second half
# permute(weights, n_head, n_head_kv):
#   if n_head_kv != n_head: partial rotation
#   else: for i in range(n_head): if i < n_head//2: swap row i with i+n_head//2

def llama_permute(w, n_head, n_head_kv):
    """GGUF LlamaModel.permute: undo the HF head-pair rotation."""
    w = w.reshape(n_head, -1).copy()
    if n_head != n_head_kv:
        n_rot = n_head_kv
    else:
        n_rot = n_head // 2
    for i in range(n_rot):
        # ggml permute logic: swap row i and i + n_head//2 (or specific pattern)
        pass
    return w

# Actually the standard llama.cpp convert permute is:
# def permute(weights, n_head, n_head_kv):
#     weights = weights.reshape((n_head, 2, weights.shape[0] // n_head // 2, *weights.shape[1:]))
#     weights = weights.transpose(0, 2, 1, ...)
#     if n_head_kv != n_head:
#         weights = weights.reshape((n_head // n_head_kv, n_head_kv, ...))
#     return weights.reshape(...)

# For n_head=24, head_dim=128, rows of Q weight are [24, 128]
# The permute reshapes to [24, 2, 64] then swaps the middle dim: [24, 64, 2] -> flat
# This is the "half-rotation" within each head

# Test: reshape ref0 to [24, 2, 64], swap middle dim -> [24, 64, 2] -> flat
ref0_r = ref0.reshape(24, 2, 64)
ref0_perm = ref0_r.transpose(0, 2, 1).flatten()
cos = np.dot(d2_q, ref0_perm)/(np.linalg.norm(d2_q)*np.linalg.norm(ref0_perm))
print(f"Half-rotation [24,2,64]->[24,64,2]: cos={cos:.6f}")

# Test: apply the same permute but keep positions
# Actually let's try: reshape output [3072] to [24, 128], swap within each head: [24,64,2] -> [24,2,64]
d2_q_r = d2_q.reshape(24, 2, 64)
ref0_r2 = ref0.reshape(24, 2, 64)

# Try all 4 combinations of transpose within heads
d2_q_p1 = d2_q_r.transpose(0, 2, 1).flatten()
d2_q_p2 = d2_q_r.transpose(0, 2, 1)[:, :, ::-1].flatten()

cos1 = np.dot(d2_q_p1, ref0)/(np.linalg.norm(d2_q_p1)*np.linalg.norm(ref0))
print(f"D2 transpose(0,2,1) vs ref: cos={cos1:.6f}")

cos2 = np.dot(d2_q_p1, ref0_perm)/(np.linalg.norm(d2_q_p1)*np.linalg.norm(ref0_perm))
print(f"D2 T(0,2,1) vs ref T(0,2,1): cos={cos2:.6f}")

# Try llama.cpp exact GGUF permute function
# From llama.cpp conversion/llama.py:
# def permute(weights, n_head, n_head_kv):
#     weights = weights.reshape((n_head, 2, weights.shape[0] // n_head // 2, *weights.shape[1:]))
#     weights = weights.transpose(0, 2, 1, *range(3, len(weights.shape)))
#     if n_head_kv is not None and n_head != n_head_kv:
#         weights = weights.reshape((n_head // n_head_kv, n_head_kv, *weights.shape[1:]))
#     return weights.reshape(weights.shape[0] * weights.shape[1], *weights.shape[2:]) if len(weights.shape) > 2 else weights.reshape(-1)

# For flat 1D [3072], n_head=24, n_head_kv=24:
# reshape to [24, 2, 64]
# transpose(0, 2, 1) -> [24, 64, 2]
# reshape flat -> [3072]

def ggml_llama_permute(w, n_head=24, n_head_kv=24):
    w = w.reshape(n_head, 2, -1)
    w = w.transpose(0, 2, 1)
    return w.flatten()

# Try various permute combinations
for name, perm_fn in [
    ("reshape[24,2,64]->T(0,2,1)", lambda w: w.reshape(24,2,64).transpose(0,2,1).flatten()),
    ("reshape[24,2,64]->T(0,2,1)->[::-1]", lambda w: w.reshape(24,2,64).transpose(0,2,1)[:,:,::-1].flatten()),
    ("reshape[24,128]->[24,2,64]->swap01", lambda w: w.reshape(24,2,64)[:,:,::-1].flatten()),
    ("reshape[24,128]->[::-1]", lambda w: w.reshape(24,128)[:,::-1].flatten()),
    ("reshape[128,24]->T", lambda w: w.reshape(128,24).T.flatten()),
]:
    d2_perm = perm_fn(d2_q)
    c = np.dot(d2_perm, ref0)/(np.linalg.norm(d2_perm)*np.linalg.norm(ref0))
    print(f"D2 {name}: cos={c:.6f}")

# Also try applying permute to ref and compare to raw d2
for name, perm_fn in [
    ("ref reshape[24,2,64]->T(0,2,1)", lambda w: w.reshape(24,2,64).transpose(0,2,1).flatten()),
    ("ref reshape[24,128]->[::-1]", lambda w: w.reshape(24,128)[:,::-1].flatten()),
    ("ref reshape[128,24]->T", lambda w: w.reshape(128,24).T.flatten()),
]:
    ref_perm = perm_fn(ref0)
    c = np.dot(d2_q, ref_perm)/(np.linalg.norm(d2_q)*np.linalg.norm(ref_perm))
    print(f"{name} vs D2: cos={c:.6f}")

# K stage comparison
print("\n=== K projection stages ===")
import glob
k_files = sorted(glob.glob(os.path.join(REF, "ref_pos10_layer0_k_layer0*.bin")))
trace_k_pc = trace10[(0,'k')]
d2_k = load_bin(find_tensor_file(10, 0, trace_k_pc, 'k'))
print(f"Deep2 K: {d2_k.shape}")
for kf in k_files:
    refk = load_bin(kf)
    if refk.shape == d2_k.shape:
        c = np.dot(d2_k, refk)/(np.linalg.norm(d2_k)*np.linalg.norm(refk))
        print(f"  {os.path.basename(kf)}: cos={c:.6f}")
    else:
        print(f"  {os.path.basename(kf)}: shape {refk.shape} != {d2_k.shape}")

# V stage comparison
print("\n=== V projection stages ===")
v_files = sorted(glob.glob(os.path.join(REF, "ref_pos10_layer0_v_layer0*.bin")))
trace_v_pc = trace10[(0,'v')]
d2_v = load_bin(find_tensor_file(10, 0, trace_v_pc, 'v'))
print(f"Deep2 V: {d2_v.shape}")
for vf in v_files:
    refv = load_bin(vf)
    if refv.shape == d2_v.shape:
        c = np.dot(d2_v, refv)/(np.linalg.norm(d2_v)*np.linalg.norm(refv))
        print(f"  {os.path.basename(vf)}: cos={c:.6f}")
    else:
        print(f"  {os.path.basename(vf)}: shape {refv.shape} != {d2_v.shape}")