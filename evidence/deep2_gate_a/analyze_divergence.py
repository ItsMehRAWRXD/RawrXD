#!/usr/bin/env python3
"""
Detailed comparison of Deep2 final norm vs reference hidden state.
"""
import os
import numpy as np

E = r"F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone"
REF = r"F:\rawrxd\evidence\deep2_gate_a\ref_head_extended"

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
    path = os.path.join(E, f"d2_pos{pos}_blk{blk_str}_pc{pc}_{clean_name}.bin")
    if os.path.exists(path):
        return path
    return None

# Load reference hidden states
ref_h9 = load_bin(os.path.join(REF, "ref_hidden_pos0.bin"))
ref_h10 = load_bin(os.path.join(REF, "ref_hidden_pos1.bin"))

# Load Deep2 final norms
# Need to find the correct tensor names from trace
import re
trace9_path = os.path.join(E, "d2_trace_pos9.txt")
with open(trace9_path, 'r') as f:
    for line in f:
        if 'out_norm' in line or 'logits' in line:
            print(f"Trace pos9: {line.strip()}")

trace10_path = os.path.join(E, "d2_trace_pos10.txt")
with open(trace10_path, 'r') as f:
    for line in f:
        if 'out_norm' in line or 'logits' in line:
            print(f"Trace pos10: {line.strip()}")

# Load Deep2 out_norm for pos9 and pos10
# From trace, out_norm is at blk=-1 (final), pc=?
d2_norm9_path = find_tensor_file(9, -1, 393, 'out_norm')
d2_norm10_path = find_tensor_file(10, -1, 393, 'out_norm')

if d2_norm9_path:
    d2_norm9 = load_bin(d2_norm9_path)
    print(f"\nDeep2 pos9 out_norm: {d2_norm9.shape}")
    print(f"Ref hidden pos9: {ref_h9.shape}")
    
    diff = ref_h9 - d2_norm9
    print(f"Max abs diff: {np.max(np.abs(diff)):.6f}")
    print(f"RMSE: {np.sqrt(np.mean(diff**2)):.6f}")
    print(f"Cosine: {np.dot(ref_h9, d2_norm9) / (np.linalg.norm(ref_h9) * np.linalg.norm(d2_norm9)):.6f}")
    
    # Show first 20 elements
    print("\nFirst 20 elements:")
    for i in range(20):
        print(f"  [{i:3d}] Ref: {ref_h9[i]:10.6f}  D2: {d2_norm9[i]:10.6f}  Diff: {diff[i]:10.6f}")

if d2_norm10_path:
    d2_norm10 = load_bin(d2_norm10_path)
    print(f"\nDeep2 pos10 out_norm: {d2_norm10.shape}")
    print(f"Ref hidden pos10: {ref_h10.shape}")
    
    diff = ref_h10 - d2_norm10
    print(f"Max abs diff: {np.max(np.abs(diff)):.6f}")
    print(f"RMSE: {np.sqrt(np.mean(diff**2)):.6f}")
    print(f"Cosine: {np.dot(ref_h10, d2_norm10) / (np.linalg.norm(ref_h10) * np.linalg.norm(d2_norm10)):.6f}")
    
    # Show first 20 elements
    print("\nFirst 20 elements:")
    for i in range(20):
        print(f"  [{i:3d}] Ref: {ref_h10[i]:10.6f}  D2: {d2_norm10[i]:10.6f}  Diff: {diff[i]:10.6f}")

# Compare Deep2 pos9 vs pos10 out_norm
if d2_norm9_path and d2_norm10_path:
    diff = d2_norm10 - d2_norm9
    print(f"\nDeep2 pos10 - pos9 out_norm:")
    print(f"Max abs diff: {np.max(np.abs(diff)):.6f}")
    print(f"RMSE: {np.sqrt(np.mean(diff**2)):.6f}")
    print(f"Cosine: {np.dot(d2_norm9, d2_norm10) / (np.linalg.norm(d2_norm9) * np.linalg.norm(d2_norm10)):.6f}")

# Compare reference pos9 vs pos10 hidden
diff = ref_h10 - ref_h9
print(f"\nRef pos10 - pos9 hidden:")
print(f"Max abs diff: {np.max(np.abs(diff)):.6f}")
print(f"RMSE: {np.sqrt(np.mean(diff**2)):.6f}")
print(f"Cosine: {np.dot(ref_h9, ref_h10) / (np.linalg.norm(ref_h9) * np.linalg.norm(ref_h10)):.6f}")

# Check layer 27 output (last transformer layer before final norm)
print("\n=== Layer 27 output (blk=27) ===")
for name in ['attn_out', 'ffn_out', 'resid_post', 'norm_out']:
    p9 = find_tensor_file(9, 27, 0, name)
    p10 = find_tensor_file(10, 27, 0, name)
    if p9 and p10:
        d9 = load_bin(p9)
        d10 = load_bin(p10)
        diff = d10 - d9
        cos = np.dot(d9, d10) / (np.linalg.norm(d9) * np.linalg.norm(d10))
        print(f"  {name}: cos={cos:.6f}, maxabs={np.max(np.abs(diff)):.6f}, shape={d9.shape}")