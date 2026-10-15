#!/usr/bin/env python3
"""
Compare Deep2 layer 27 output (resid2) against reference hidden state.
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

def compare(name, ref, d2):
    diff = ref - d2
    cos = np.dot(ref, d2) / (np.linalg.norm(ref) * np.linalg.norm(d2))
    maxabs = np.max(np.abs(diff))
    rmse = np.sqrt(np.mean(diff**2))
    print(f"{name}: cos={cos:.6f}, maxabs={maxabs:.6f}, rmse={rmse:.6f}")
    return cos, maxabs, rmse

# Load reference
ref_h9 = load_bin(os.path.join(REF, "ref_hidden_pos0.bin"))
ref_h10 = load_bin(os.path.join(REF, "ref_hidden_pos1.bin"))

# Load Deep2 layer 27 tensors and final norm
for pos, ref_h, pos_name in [(9, ref_h9, "pos9"), (10, ref_h10, "pos10")]:
    print(f"\n=== {pos_name} ===")
    
    # Layer 27 outputs
    resid2 = load_bin(find_tensor_file(pos, 27, 392, 'resid2'))
    out_norm = load_bin(find_tensor_file(pos, -1, 393, 'out_norm'))
    
    print(f"Layer 27 resid2: {resid2.shape}")
    print(f"Final out_norm:  {out_norm.shape}")
    print(f"Reference:       {ref_h.shape}")
    
    # Compare resid2 (layer output) vs reference
    print("\nresid2 vs reference (should match if final norm is identity-ish):")
    compare("resid2", ref_h, resid2)
    
    # Compare out_norm vs reference
    print("\nout_norm vs reference (should match closely):")
    compare("out_norm", ref_h, out_norm)
    
    # Compare resid2 vs out_norm (final norm effect)
    print("\nresid2 vs out_norm (final norm effect):")
    compare("final_norm", out_norm, resid2)

# Now let's check layer 0 input (embeddings) to see if token embedding is correct
print("\n=== Layer 0 input (embeddings) ===")
for pos in [9, 10]:
    # The first tensor in trace is usually embeddings
    emb_path = find_tensor_file(pos, 0, 0, 'embd')
    if not emb_path:
        # Try to find the first tensor
        for pc in range(10):
            emb_path = find_tensor_file(pos, 0, pc, 'embd')
            if emb_path:
                break
    if emb_path:
        emb = load_bin(emb_path)
        print(f"pos{pos} embd: {emb.shape}")
        # We don't have reference embeddings, but we can check pos9 vs pos10
    else:
        print(f"pos{pos} embd: NOT FOUND")

# Compare Deep2 pos9 vs pos10 at each layer to see expected changes
print("\n=== Deep2 pos9 vs pos10 at key layers ===")
for blk in [0, 5, 10, 15, 20, 25, 27]:
    for name in ['resid_in', 'attn_norm', 'attn_out', 'resid1', 'ffn_norm', 'resid2']:
        p9 = find_tensor_file(9, blk, 0, name)
        p10 = find_tensor_file(10, blk, 0, name)
        # Need to find correct pc for each
        # Let's just search by name
        for pc in range(400):
            p9 = find_tensor_file(9, blk, pc, name)
            if p9:
                p10 = find_tensor_file(10, blk, pc, name)
                if p10:
                    d9 = load_bin(p9)
                    d10 = load_bin(p10)
                    diff = d10 - d9
                    cos = np.dot(d9, d10) / (np.linalg.norm(d9) * np.linalg.norm(d10))
                    maxabs = np.max(np.abs(diff))
                    if cos < 0.999:
                        print(f"  blk={blk:2d} pc={pc:3d} {name:12s} cos={cos:.6f} maxabs={maxabs:.6f}")
                break