#!/usr/bin/env python3
"""
Compare Deep2 full logits (d2_logits_pos*.bin) with reference logits.
"""
import os
import numpy as np

D2 = r"F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone"
REF = r"F:\rawrxd\evidence\deep2_gate_a\ref_head_extended"

def load_bin(path, dtype='<f4'):
    with open(path, 'rb') as f:
        data = f.read()
    return np.frombuffer(data, dtype=dtype).astype(np.float64)

def compare(name, ref, d2):
    diff = ref - d2
    cos = np.dot(ref, d2) / (np.linalg.norm(ref) * np.linalg.norm(d2))
    maxabs = np.max(np.abs(diff))
    rmse = np.sqrt(np.mean(diff**2))
    print(f"{name}: cos={cos:.10f}, maxabs={maxabs:.6e}, rmse={rmse:.6e}")
    # Argmax
    ref_argmax = np.argmax(ref)
    d2_argmax = np.argmax(d2)
    print(f"  Ref argmax: {ref_argmax}, D2 argmax: {d2_argmax}, Match: {ref_argmax == d2_argmax}")
    return cos, maxabs, rmse

# Compare pos9 and pos10
for pos in [9, 10]:
    print(f"\n=== pos{pos} ===")
    d2_logits = load_bin(os.path.join(D2, f"d2_logits_pos{pos}.bin"))
    ref_logits = load_bin(os.path.join(REF, f"ref_logits_pos{pos}.bin"))
    
    print(f"Deep2 logits: {d2_logits.shape}")
    print(f"Ref logits:   {ref_logits.shape}")
    
    compare(f"pos{pos}_logits", ref_logits, d2_logits)

# Also check the trace "logits" operation (pre-LM-head hidden state)
# Compare with reference hidden state
for pos, ref_name in [(9, "pos0"), (10, "pos1")]:
    print(f"\n=== pos{pos} pre-LM-head (traced logits op) vs ref hidden ===")
    d2_hidden = load_bin(os.path.join(D2, f"d2_pos{pos}_blk999_pc394_logits.bin"))
    ref_hidden = load_bin(os.path.join(REF, f"ref_hidden_{ref_name}.bin"))
    
    print(f"Deep2 traced logits: {d2_hidden.shape}")
    print(f"Ref hidden:          {ref_hidden.shape}")
    
    compare(f"pos{pos}_traced_logits", ref_hidden, d2_hidden)

# Compare Deep2 out_norm vs traced logits (should be same)
for pos in [9, 10]:
    d2_norm = load_bin(os.path.join(D2, f"d2_pos{pos}_blk999_pc393_out_norm.bin"))
    d2_logits_op = load_bin(os.path.join(D2, f"d2_pos{pos}_blk999_pc394_logits.bin"))
    diff = d2_norm - d2_logits_op
    print(f"\npos{pos} out_norm vs traced logits op: maxabs={np.max(np.abs(diff)):.6e}, allclose={np.allclose(d2_norm, d2_logits_op)}")