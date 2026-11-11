#!/usr/bin/env python3
"""
Gate A Divergence Diagnostic: Compare Deep2 intermediate tensors at positions 9 and 10
to identify where numerical drift begins.
"""
import os
import struct
import numpy as np

E = r"F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone"

def load_bin(path):
    """Load binary float32 tensor."""
    with open(path, 'rb') as f:
        data = f.read()
    return np.frombuffer(data, dtype='<f4').astype(np.float64)

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

def parse_trace(trace_path):
    """Parse Deep2 trace file to get tensor metadata."""
    tensors = []
    with open(trace_path, 'r') as f:
        for line in f:
            if line.startswith('blk='):
                # Parse: blk=0 pc=2 op=1 name=attn_norm size=3072 vals=...
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

def find_tensor_file(pos, blk, pc, name):
    """Find the binary file for a given tensor."""
    # Sanitize name like deep2_parity_trace.cpp does
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

# Parse traces for positions 9 and 10
print("=== Parsing Deep2 traces ===")
trace9 = parse_trace(os.path.join(E, "d2_trace_pos9.txt"))
trace10 = parse_trace(os.path.join(E, "d2_trace_pos10.txt"))

print(f"Position 9: {len(trace9)} tensors")
print(f"Position 10: {len(trace10)} tensors")

# Compare tensor-by-tensor between pos 9 and pos 10 (looking for where they diverge in Deep2)
print("\n=== Deep2 pos9 vs pos10 internal comparison ===")
# We compare same layer/op between positions to see where values start diverging

# Since we don't have llama.cpp reference intermediate tensors yet,
# let's at least analyze the Deep2 tensor evolution from pos9 to pos10
# and identify which tensors change the most

for i, (t9, t10) in enumerate(zip(trace9, trace10)):
    if t9['name'] == t10['name'] and t9['blk'] == t10['blk'] and t9['pc'] == t10['pc']:
        p9 = find_tensor_file(9, t9['blk'], t9['pc'], t9['name'])
        p10 = find_tensor_file(10, t10['blk'], t10['pc'], t10['name'])
        if p9 and p10:
            d9 = load_bin(p9)
            d10 = load_bin(p10)
            diff = d10 - d9
            maxabs = float(np.max(np.abs(diff)))
            if maxabs > 0.1:  # Significant change
                print(f"  Layer {t9['blk']} {t9['name']}: max change = {maxabs:.6f}")

print("\n=== Summary ===")
print("Need llama.cpp reference intermediate tensors for full comparison.")
print("Current reference only has logits and final hidden state.")
print("Next step: Build extended llama.cpp dumper that captures layer-by-layer tensors.")