#!/usr/bin/env python3
"""
Gate A parity: compare Deep2 vs llama.cpp using CORRECT reference stages.
llama.cpp emits multiple callbacks per tensor name; stage1 is the one matching
Deep2's capture point (post-GEMV, pre-consumer).
"""
import os, glob
import numpy as np

D2 = r"F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone"
REF = r"F:\rawrxd\evidence\deep2_gate_a\ref_intermediate_v2"

def load_bin(p):
    with open(p,'rb') as f: return np.frombuffer(f.read(),dtype='<f4').astype(np.float64)

def build_trace(pos):
    m={}
    with open(os.path.join(D2,f"d2_trace_pos{pos}.txt")) as f:
        for line in f:
            if line.startswith('blk='):
                p=line.strip().split()
                m[(int(p[0].split('=')[1]),p[3].split('=')[1])]=int(p[1].split('=')[1])
    return m

def d2_tensor(pos, layer, name):
    blk = 999 if layer<0 else layer
    trace = build_trace(pos)
    pc = trace.get((layer,name), 0)
    path = os.path.join(D2, f"d2_pos{pos}_blk{blk}_pc{pc}_{name}.bin")
    if not os.path.exists(path):
        # try sanitized variants
        nm = ''.join(c if (c.isalnum() or c in '-_.') else '_' for c in name)
        path = os.path.join(D2, f"d2_pos{pos}_blk{blk}_pc{pc}_{nm}.bin")
    return load_bin(path) if os.path.exists(path) else None

def ref_tensor(pos, layer, name, stage=1):
    base = os.path.join(REF, f"ref_pos{pos}_layer{layer}_{name}_layer{layer}")
    cand = base + ("" if stage==0 else f"_stage{stage}") + ".bin"
    if not os.path.exists(cand) and stage != 0:
        cand = base + ".bin"
    return load_bin(cand) if os.path.exists(cand) else None

def cos(a,b):
    if a.shape!=b.shape: return None
    return float(np.dot(a,b)/(np.linalg.norm(a)*np.linalg.norm(b)))

def full_cmp(pos):
    """Full comparison for one position. Returns per-tensor results."""
    results={}
    # Layer tensors
    for layer in range(28):
        for name in ['attn_norm','q','k','v','attn_out','ffn_norm','gate','up','swiglu','ffn_out']:
            d2 = d2_tensor(pos, layer, name)
            ref = ref_tensor(pos, layer, name, 1)
            if d2 is not None and ref is not None:
                c = cos(d2, ref)
                if c is not None:
                    results[f"L{layer}.{name}"] = c
    return results

# Run comparison
print("=" * 70)
print("GATE A — NUMERICAL PARITY (corrected reference stage selection)")
print("=" * 70)

for pos in [9, 10]:
    r = full_cmp(pos)
    fails = {k:v for k,v in r.items() if v < 0.999}
    passes = len(r) - len(fails)
    print(f"\nPosition {pos}: {passes}/{len(r)} tensors PASS (>=0.999)")
    print(f"  Min cosine: {min(r.values()):.6f}")
    print(f"  Mean cosine: {np.mean(list(r.values())):.6f}")
    if fails:
        print("  FAILS (<0.999):")
        for k in sorted(fails, key=lambda x: fails[x])[:10]:
            print(f"    {k}: {fails[k]:.6f}")
    else:
        print("  ALL TENSORS PASS")

# Logits
for pos in [9, 10]:
    d2 = load_bin(os.path.join(D2, f"d2_logits_pos{pos}.bin"))
    ref = load_bin(os.path.join(REF, f"ref_logits_pos{pos}.bin"))
    c = cos(d2, ref)
    diff = d2 - ref
    argmax_match = np.argmax(d2) == np.argmax(ref)
    print(f"\nPosition {pos} logits: cos={c:.10f}, maxabs={np.max(np.abs(diff)):.6e}, "
          f"argmax_match={argmax_match}")