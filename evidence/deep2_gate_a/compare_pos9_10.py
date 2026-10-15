#!/usr/bin/env python3
"""
Compare Deep2 trace tensors against llama.cpp reference for positions 9 and 10.
"""
import os
import struct
import numpy as np

E = r"F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone"
REF = r"F:\rawrxd\evidence\deep2_gate_a\ref_head_extended"

def load_bin(path, dtype='<f4'):
    """Load binary tensor."""
    with open(path, 'rb') as f:
        data = f.read()
    return np.frombuffer(data, dtype=dtype).astype(np.float64)

def compare_tensors(name, ref, d2):
    """Compare two tensors and return metrics."""
    if ref.shape != d2.shape:
        return {"error": f"Shape mismatch: ref={ref.shape}, d2={d2.shape}"}
    
    diff = ref - d2
    maxabs = float(np.max(np.abs(diff)))
    rmse = float(np.sqrt(np.mean(diff * diff)))
    denom = float(np.linalg.norm(ref) * np.linalg.norm(d2))
    cos = float(np.dot(ref, d2) / denom) if denom > 0 else 0.0
    
    # Find first significant mismatch
    mismatch_idx = None
    for i, (r, d) in enumerate(zip(ref.flat, d2.flat)):
        if abs(r - d) > 1e-4:
            mismatch_idx = i
            break
    
    return {
        "name": name,
        "shape": ref.shape,
        "cosine": cos,
        "max_abs": maxabs,
        "rmse": rmse,
        "first_mismatch_idx": mismatch_idx,
        "ref_range": (float(np.min(ref)), float(np.max(ref))),
        "d2_range": (float(np.min(d2)), float(np.max(d2)))
    }

def find_tensor_file(pos, blk, pc, name):
    """Find the binary file for a given tensor."""
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

# Parse Deep2 trace for positions 9 and 10
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
                tensors.append({
                    'blk': blk, 'pc': pc, 'op': op, 'name': name, 'size': size
                })
    return tensors

trace9 = parse_trace(os.path.join(E, "d2_trace_pos9.txt"))
trace10 = parse_trace(os.path.join(E, "d2_trace_pos10.txt"))

print(f"Position 9: {len(trace9)} tensors")
print(f"Position 10: {len(trace10)} tensors")

# Load reference data
# Note: ref_hidden_pos0.bin corresponds to position 9 (first token in tokens file)
#       ref_hidden_pos1.bin corresponds to position 10 (second token)
ref_hidden_9 = load_bin(os.path.join(REF, "ref_hidden_pos0.bin"))
ref_hidden_10 = load_bin(os.path.join(REF, "ref_hidden_pos1.bin"))
ref_logits_9 = load_bin(os.path.join(REF, "ref_logits_pos0.bin"))
ref_logits_10 = load_bin(os.path.join(REF, "ref_logits_pos1.bin"))

print(f"\nReference hidden 9: {ref_hidden_9.shape}")
print(f"Reference hidden 10: {ref_hidden_10.shape}")
print(f"Reference logits 9: {ref_logits_9.shape}")
print(f"Reference logits 10: {ref_logits_10.shape}")

# Find Deep2 final norm and logits
# Deep2 trace: last few entries are out_norm (final norm) and logits
for pos, trace, ref_h, ref_l, pos_name in [
    (9, trace9, ref_hidden_9, ref_logits_9, "pos9"),
    (10, trace10, ref_hidden_10, ref_logits_10, "pos10")
]:
    print(f"\n=== {pos_name} ===")
    
    # Find final norm (out_norm) and logits
    norm_tensor = None
    logits_tensor = None
    for t in trace:
        if t['name'] == 'out_norm':
            norm_tensor = t
        if t['name'] == 'logits':
            logits_tensor = t
    
    if norm_tensor:
        d2_norm_path = find_tensor_file(pos, norm_tensor['blk'], norm_tensor['pc'], norm_tensor['name'])
        if d2_norm_path:
            d2_norm = load_bin(d2_norm_path)
            print(f"Deep2 norm: {d2_norm.shape}")
            metrics = compare_tensors(f"{pos_name}_final_norm", ref_h, d2_norm)
            print(f"  Cosine: {metrics['cosine']:.10f}")
            print(f"  MaxAbs: {metrics['max_abs']:.6e}")
            print(f"  RMSE:   {metrics['rmse']:.6e}")
            print(f"  Mismatch idx: {metrics['first_mismatch_idx']}")
            print(f"  Ref range: [{metrics['ref_range'][0]:.4f}, {metrics['ref_range'][1]:.4f}]")
            print(f"  D2  range: [{metrics['d2_range'][0]:.4f}, {metrics['d2_range'][1]:.4f}]")
    
    if logits_tensor:
        d2_logits_path = find_tensor_file(pos, logits_tensor['blk'], logits_tensor['pc'], logits_tensor['name'])
        if d2_logits_path:
            d2_logits = load_bin(d2_logits_path)
            print(f"Deep2 logits: {d2_logits.shape}")
            metrics = compare_tensors(f"{pos_name}_logits", ref_l, d2_logits)
            print(f"  Cosine: {metrics['cosine']:.10f}")
            print(f"  MaxAbs: {metrics['max_abs']:.6e}")
            print(f"  RMSE:   {metrics['rmse']:.6e}")
            print(f"  Mismatch idx: {metrics['first_mismatch_idx']}")
            print(f"  Ref range: [{metrics['ref_range'][0]:.4f}, {metrics['ref_range'][1]:.4f}]")
            print(f"  D2  range: [{metrics['d2_range'][0]:.4f}, {metrics['d2_range'][1]:.4f}]")

# Also compare layer-by-layer for position 9 and 10
# Find common tensor names between traces
print("\n=== Layer-by-layer comparison (pos9 vs pos10 Deep2) ===")
trace9_dict = {(t['blk'], t['pc'], t['name']): t for t in trace9}
trace10_dict = {(t['blk'], t['pc'], t['name']): t for t in trace10}

common_keys = set(trace9_dict.keys()) & set(trace10_dict.keys())
for key in sorted(common_keys):
    t9 = trace9_dict[key]
    t10 = trace10_dict[key]
    
    p9 = find_tensor_file(9, t9['blk'], t9['pc'], t9['name'])
    p10 = find_tensor_file(10, t10['blk'], t10['pc'], t10['name'])
    
    if p9 and p10:
        d9 = load_bin(p9)
        d10 = load_bin(p10)
        diff = d10 - d9
        maxabs = float(np.max(np.abs(diff)))
        if maxabs > 0.01:  # Only show significant changes
            denom = float(np.linalg.norm(d9) * np.linalg.norm(d10))
            cos = float(np.dot(d9, d10) / denom) if denom > 0 else 0.0
            if cos < 0.999:
                print(f"  blk={t9['blk']:2d} pc={t9['pc']:3d} {t9['name']:30s} cos={cos:.6f} maxabs={maxabs:.6f}")

print("\n=== Key tensors to check against reference ===")
# Check if we can identify the first divergent layer by comparing 
# Deep2 pos9 tensors against expected reference (we don't have reference for these)
# But we can at least check if the final norm matches reference hidden state