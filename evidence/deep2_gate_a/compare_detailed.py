#!/usr/bin/env python3
"""
Detailed layer-by-layer comparison of Deep2 vs llama.cpp reference at position 10.
"""
import os
import numpy as np

D2 = r"F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone"
REF = r"F:\rawrxd\evidence\deep2_gate_a\ref_intermediate_v2"

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

def compare(name, ref, d2):
    if ref.shape != d2.shape:
        print(f"  {name}: SHAPE MISMATCH ref={ref.shape} d2={d2.shape}")
        return None
    diff = ref - d2
    cos = np.dot(ref, d2) / (np.linalg.norm(ref) * np.linalg.norm(d2))
    maxabs = np.max(np.abs(diff))
    rmse = np.sqrt(np.mean(diff**2))
    mismatch_idx = None
    for i, (r, d) in enumerate(zip(ref.flat, d2.flat)):
        if abs(r - d) > 1e-4:
            mismatch_idx = i
            break
    print(f"  {name}: cos={cos:.6f}, maxabs={maxabs:.6f}, rmse={rmse:.6f}, mismatch_idx={mismatch_idx}, shape={ref.shape}")
    return cos, maxabs, rmse, mismatch_idx

# Parse Deep2 trace for position 10
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

print("=== Position 10: Deep2 vs Reference Layer-by-Layer ===\n")

# Layer -1 (final) - embedding
d2_embd = load_bin(find_tensor_file(10, -1, 0, 'token_embd.weight'))
ref_embd = load_bin(os.path.join(REF, "ref_pos10_layer-1_embd.bin"))
print("Embedding:")
compare("embd", ref_embd, d2_embd)

# Layer 0
print("\nLayer 0:")
for name in ['attn_norm', 'q', 'k', 'v', 'attn_out', 'resid1', 'ffn_norm', 'gate', 'up', 'swiglu', 'ffn_out', 'resid2']:
    d2_path = find_tensor_file(10, 0, trace10_map.get((0, name)), name)
    if d2_path:
        ref_path = os.path.join(REF, f"ref_pos10_layer0_{name}_layer0.bin")
        if os.path.exists(ref_path):
            d2 = load_bin(d2_path)
            ref = load_bin(ref_path)
            compare(name, ref, d2)
        else:
            print(f"  {name}: REF NOT FOUND")
    else:
        print(f"  {name}: D2 NOT FOUND")

# Layer 1
print("\nLayer 1:")
for name in ['attn_norm', 'q', 'k', 'v', 'attn_out', 'resid1', 'ffn_norm', 'gate', 'up', 'swiglu', 'ffn_out', 'resid2']:
    d2_path = find_tensor_file(10, 1, trace10_map.get((1, name)), name)
    if d2_path:
        ref_path = os.path.join(REF, f"ref_pos10_layer1_{name}_layer1.bin")
        if os.path.exists(ref_path):
            d2 = load_bin(d2_path)
            ref = load_bin(ref_path)
            compare(name, ref, d2)
        else:
            print(f"  {name}: REF NOT FOUND")
    else:
        print(f"  {name}: D2 NOT FOUND")

# Layer 2
print("\nLayer 2:")
for name in ['attn_norm', 'q', 'k', 'v', 'attn_out', 'resid1', 'ffn_norm', 'gate', 'up', 'swiglu', 'ffn_out', 'resid2']:
    d2_path = find_tensor_file(10, 2, trace10_map.get((2, name)), name)
    if d2_path:
        ref_path = os.path.join(REF, f"ref_pos10_layer2_{name}_layer2.bin")
        if os.path.exists(ref_path):
            d2 = load_bin(d2_path)
            ref = load_bin(ref_path)
            compare(name, ref, d2)
        else:
            print(f"  {name}: REF NOT FOUND")
    else:
        print(f"  {name}: D2 NOT FOUND")

# Layer 27 (last)
print("\nLayer 27:")
for name in ['attn_norm', 'q', 'k', 'v', 'attn_out', 'resid1', 'ffn_norm', 'gate', 'up', 'swiglu', 'ffn_out', 'resid2']:
    d2_path = find_tensor_file(10, 27, trace10_map.get((27, name)), name)
    if d2_path:
        ref_path = os.path.join(REF, f"ref_pos10_layer27_{name}_layer27.bin")
        if os.path.exists(ref_path):
            d2 = load_bin(d2_path)
            ref = load_bin(ref_path)
            compare(name, ref, d2)
        else:
            print(f"  {name}: REF NOT FOUND")
    else:
        print(f"  {name}: D2 NOT FOUND")

# Final norm and logits
print("\nFinal norm & logits:")
d2_norm = load_bin(find_tensor_file(10, -1, 393, 'out_norm'))
ref_hidden = load_bin(os.path.join(REF, "ref_hidden_pos10.bin"))
print("Final norm (Deep2 out_norm vs Ref hidden):")
compare("final_norm", ref_hidden, d2_norm)

d2_logits = load_bin(os.path.join(D2, "d2_logits_pos10.bin"))
ref_logits = load_bin(os.path.join(REF, "ref_logits_pos10.bin"))
print("Logits:")
compare("logits", ref_logits, d2_logits)

# Also compare Deep2 pos9 vs pos10 at layer 0 to see expected differences
print("\n=== Deep2 pos9 vs pos10 at Layer 0 (sanity) ===")
trace9_map = {}
trace9_path = os.path.join(D2, "d2_trace_pos9.txt")
with open(trace9_path, 'r') as f:
    for line in f:
        if line.startswith('blk='):
            parts = line.strip().split()
            blk = int(parts[0].split('=')[1])
            pc = int(parts[1].split('=')[1])
            op = int(parts[2].split('=')[1])
            name = parts[3].split('=')[1]
            size = int(parts[4].split('=')[1])
            trace9_map[(blk, name)] = pc

for name in ['resid_in', 'attn_norm', 'q', 'k', 'v', 'attn_out', 'resid1', 'ffn_norm', 'gate', 'up', 'swiglu', 'ffn_out', 'resid2']:
    pc9 = trace9_map.get((0, name))
    pc10 = trace10_map.get((0, name))
    if pc9 and pc10:
        d9 = load_bin(find_tensor_file(9, 0, pc9, name))
        d10 = load_bin(find_tensor_file(10, 0, pc10, name))
        diff = d10 - d9
        cos = np.dot(d9, d10) / (np.linalg.norm(d9) * np.linalg.norm(d10))
        maxabs = np.max(np.abs(diff))
        if cos < 0.99:
            print(f"  {name}: cos={cos:.6f}, maxabs={maxabs:.6f}")

# Reference pos9 vs pos10 at layer 0
print("\n=== Reference pos9 vs pos10 at Layer 0 ===")
for name in ['attn_norm', 'q', 'k', 'v', 'attn_out', 'ffn_norm', 'gate', 'up', 'swiglu', 'ffn_out', 'resid']:
    ref9 = load_bin(os.path.join(REF, f"ref_pos9_layer0_{name}_layer0.bin"))
    ref10 = load_bin(os.path.join(REF, f"ref_pos10_layer0_{name}_layer0.bin"))
    diff = ref10 - ref9
    cos = np.dot(ref9, ref10) / (np.linalg.norm(ref9) * np.linalg.norm(ref10))
    maxabs = np.max(np.abs(diff))
    if cos < 0.99:
        print(f"  {name}: cos={cos:.6f}, maxabs={maxabs:.6f}")