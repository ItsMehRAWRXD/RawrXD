#!/usr/bin/env python3
"""
Compare Deep2 trace tensors against llama.cpp reference intermediate tensors.
"""
import os
import numpy as np

D2 = r"F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone"
REF = r"F:\rawrxd\evidence\deep2_gate_a\ref_intermediate"

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
    diff = ref - d2
    cos = np.dot(ref, d2) / (np.linalg.norm(ref) * np.linalg.norm(d2))
    maxabs = np.max(np.abs(diff))
    rmse = np.sqrt(np.mean(diff**2))
    mismatch_idx = None
    for i, (r, d) in enumerate(zip(ref.flat, d2.flat)):
        if abs(r - d) > 1e-4:
            mismatch_idx = i
            break
    print(f"  {name}: cos={cos:.6f}, maxabs={maxabs:.6f}, rmse={rmse:.6f}, mismatch_idx={mismatch_idx}")
    return cos, maxabs, rmse, mismatch_idx

# Parse Deep2 trace to find tensor names at each layer
import re

trace9_path = os.path.join(D2, "d2_trace_pos9.txt")
trace10_path = os.path.join(D2, "d2_trace_pos10.txt")

def parse_trace(trace_path):
    tensors = []
    with open(trace_path, 'r') as f:
        for line in f:
            if line.startswith('blk='):
                parts = line.strip().split()
                blk = int(parts[0].split('=')[1])
                pc = int(parts[1].split('=')[1])
                op = int(parts[2].split('=')[1])
                name = parts[3].split('=')[1]
                size = int(parts[4].split('=')[1])
                tensors.append({'blk': blk, 'pc': pc, 'op': op, 'name': name, 'size': size})
    return tensors

trace9 = parse_trace(trace9_path)
trace10 = parse_trace(trace10_path)

# Build mapping of (blk, name) -> pc for each position
trace9_map = {(t['blk'], t['name']): t['pc'] for t in trace9}
trace10_map = {(t['blk'], t['name']): t['pc'] for t in trace10}

print("=== Comparing Deep2 vs llama.cpp reference at position 9 (token 5679) ===")

# The reference only has layer -1 (final layer), so we can only compare the final outputs
# But let's check if we can compare the final norm and logits

# Deep2 final norm (out_norm) at pos9
d2_norm9 = load_bin(find_tensor_file(9, -1, 393, 'out_norm'))
# Reference doesn't have out_norm for final layer, use attn_norm from layer -1
# Actually the reference has attn_norm, attn_out, ffn_norm, ffn_out, resid for final layer
ref_norm9 = load_bin(os.path.join(REF, "ref_pos0_layer-1_attn_norm.bin"))
print("Final layer attn_norm pos9 (Deep2 out_norm vs Ref attn_norm):")
compare("out_norm_pos9", ref_norm9, d2_norm9)

# Deep2 full logits at pos9 (128256)
d2_logits9 = load_bin(os.path.join(D2, "d2_logits_pos9.bin"))
ref_logits9 = load_bin(os.path.join(REF, "ref_logits_pos0.bin"))
print("Full logits pos9:")
compare("logits_pos9", ref_logits9, d2_logits9)

# Deep2 embd at pos9 (first layer input)
# Deep2 trace shows token_embd.weight at pc=0, then resid_in at pc=1
d2_embd9 = load_bin(find_tensor_file(9, -1, 0, 'token_embd.weight'))
ref_embd9 = load_bin(os.path.join(REF, "ref_pos0_layer-1_embd.bin"))
print("Embedding pos9:")
compare("embd_pos9", ref_embd9, d2_embd9)

print("\n=== Comparing Deep2 vs llama.cpp reference at position 10 (token 13) ===")

d2_norm10 = load_bin(find_tensor_file(10, -1, 393, 'out_norm'))
ref_norm10 = load_bin(os.path.join(REF, "ref_pos1_layer-1_attn_norm.bin"))
print("Final layer attn_norm pos10 (Deep2 out_norm vs Ref attn_norm):")
compare("out_norm_pos10", ref_norm10, d2_norm10)

# Deep2 full logits at pos10 (128256)
d2_logits10 = load_bin(os.path.join(D2, "d2_logits_pos10.bin"))
ref_logits10 = load_bin(os.path.join(REF, "ref_logits_pos1.bin"))
print("Full logits pos10:")
compare("logits_pos10", ref_logits10, d2_logits10)

d2_embd10 = load_bin(find_tensor_file(10, -1, 0, 'token_embd.weight'))
ref_embd10 = load_bin(os.path.join(REF, "ref_pos1_layer-1_embd.bin"))
print("Embedding pos10:")
compare("embd_pos10", ref_embd10, d2_embd10)

# Also compare Deep2 pos9 vs pos10 internal evolution
print("\n=== Deep2 pos9 vs pos10 internal comparison (sanity check) ===")
for blk in [0, 5, 10, 15, 20, 25, 27]:
    for name in ['resid_in', 'attn_norm', 'q', 'k', 'v', 'attn_out', 'resid1', 'ffn_norm', 'gate', 'up', 'ffn_out', 'resid2']:
        pc9 = trace9_map.get((blk, name))
        pc10 = trace10_map.get((blk, name))
        if pc9 is not None and pc10 is not None:
            p9 = find_tensor_file(9, blk, pc9, name)
            p10 = find_tensor_file(10, blk, pc10, name)
            if p9 and p10:
                d9 = load_bin(p9)
                d10 = load_bin(p10)
                diff = d10 - d9
                cos = np.dot(d9, d10) / (np.linalg.norm(d9) * np.linalg.norm(d10))
                maxabs = np.max(np.abs(diff))
                if cos < 0.99:
                    print(f"  blk={blk:2d} {name:12s} cos={cos:.6f} maxabs={maxabs:.6f}")

# Now let's check layer-by-layer for pos9 vs pos10 in reference
# The reference only has layer -1, so we can't do layer-by-layer yet
print("\n=== Reference only has layer -1 tensors ===")
print("Need to fix reference dumper to capture per-layer tensors")