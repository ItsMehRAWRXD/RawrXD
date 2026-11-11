#!/usr/bin/env python3
"""
FIXED Gate A parity comparison: use the CORRECT reference tensor stage.
Deep2 captures the raw GEMV output; llama.cpp emits multiple callbacks with
the same name at different graph stages. Stage 1/2/3 [128,24,1,1] reshape
of the flat [3072] GEMV output matches Deep2's pre-RoPE projection.
"""
import os, glob
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

def compare(name, ref, d2):
    if ref.shape != d2.shape:
        return None
    diff = ref - d2
    cos = np.dot(ref, d2)/(np.linalg.norm(ref)*np.linalg.norm(d2))
    maxabs = np.max(np.abs(diff)); rmse = np.sqrt(np.mean(diff**2))
    return cos, maxabs, rmse

# Build Deep2 trace maps
def build_trace(pos):
    m = {}
    with open(os.path.join(D2, f"d2_trace_pos{pos}.txt")) as f:
        for line in f:
            if line.startswith('blk='):
                p = line.strip().split()
                m[(int(p[0].split('=')[1]), p[3].split('=')[1])] = int(p[1].split('=')[1])
    return m

def get_ref(pos, layer, name, prefer_stage=1):
    """Find the reference tensor matching Deep2's raw GEMV stage."""
    base = os.path.join(REF, f"ref_pos{pos}_layer{layer}_{name}_layer{layer}")
    if prefer_stage == 0:
        cand = base + ".bin"
    else:
        cand = base + f"_stage{prefer_stage}.bin"
    if os.path.exists(cand):
        return load_bin(cand)
    return None

POSITIONS = [9, 10]
all_pass = True

for pos in POSITIONS:
    trace = build_trace(pos)
    print(f"\n{'='*60}")
    print(f"POSITION {pos}")
    print(f"{'='*60}")
    
    # Embedding - stored as blk=999 in filenames
    d2 = load_bin(find_tensor_file(pos, 999, trace.get((-1,'token_embd.weight'), 0), 'token_embd.weight'))
    ref = load_bin(os.path.join(REF, f"ref_pos{pos}_layer-1_embd.bin"))
    r = compare("embd", ref, d2)
    print(f"  embd:        cos={r[0]:.10f}  maxabs={r[1]:.2e}  {'PASS' if r[0]>=0.999 else 'FAIL'}")
    if r[0] < 0.999: all_pass = False
    
    # Per layer
    for layer in range(28):
        layer_ok = True
        metrics = []
        
        # attn_norm
        d2 = load_bin(find_tensor_file(pos, layer, trace.get((layer,'attn_norm')), 'attn_norm'))
        ref = get_ref(pos, layer, 'attn_norm', 0)
        if ref is not None and ref.shape == d2.shape:
            r = compare("attn_norm", ref, d2)
            metrics.append(f"norm={r[0]:.6f}")
            if r[0] < 0.999: layer_ok = False
        
        # q projection - use stage1 (raw GEMV reshaped to [H,D])
        d2 = load_bin(find_tensor_file(pos, layer, trace.get((layer,'q')), 'q'))
        ref = get_ref(pos, layer, 'q', 1)
        if ref is None: ref = get_ref(pos, layer, 'q', 0)
        if ref is not None and ref.shape == d2.shape:
            r = compare("q", ref, d2)
            metrics.append(f"q={r[0]:.6f}")
            if r[0] < 0.999: layer_ok = False
        
        # k projection - use stage1
        d2 = load_bin(find_tensor_file(pos, layer, trace.get((layer,'k')), 'k'))
        ref = get_ref(pos, layer, 'k', 1)
        if ref is None: ref = get_ref(pos, layer, 'k', 0)
        if ref is not None and ref.shape == d2.shape:
            r = compare("k", ref, d2)
            metrics.append(f"k={r[0]:.6f}")
            if r[0] < 0.999: layer_ok = False
        
        # v projection - use stage1
        d2 = load_bin(find_tensor_file(pos, layer, trace.get((layer,'v')), 'v'))
        ref = get_ref(pos, layer, 'v', 1)
        if ref is None: ref = get_ref(pos, layer, 'v', 0)
        if ref is not None and ref.shape == d2.shape:
            r = compare("v", ref, d2)
            metrics.append(f"v={r[0]:.6f}")
            if r[0] < 0.999: layer_ok = False
        
        # ffn tensors
        for nm in ['ffn_norm', 'gate', 'up', 'swiglu', 'ffn_out']:
            d2 = load_bin(find_tensor_file(pos, layer, trace.get((layer,nm)), nm))
            ref = get_ref(pos, layer, nm, 0)
            if ref is not None and ref.shape == d2.shape:
                r = compare(nm, ref, d2)
                metrics.append(f"{nm}={r[0]:.6f}")
                if r[0] < 0.999: layer_ok = False
        
        status = "PASS" if layer_ok else "FAIL"
        print(f"  L{layer:2d} {status}: {' '.join(metrics)}")
        if not layer_ok: all_pass = False
    
    # Final norm and logits
    d2 = load_bin(os.path.join(D2, f"d2_logits_pos{pos}.bin"))
    ref = load_bin(os.path.join(REF, f"ref_logits_pos{pos}.bin"))
    r = compare("logits", ref, d2)
    print(f"\n  LOGITS: cos={r[0]:.10f}  maxabs={r[1]:.6e}  rmse={r[2]:.6e}  {'PASS' if r[0]>=0.999 else 'FAIL'}")
    if r[0] < 0.999: all_pass = False

print(f"\n{'='*60}")
print(f"OVERALL: {'PASS' if all_pass else 'FAIL'}")
print(f"{'='*60}")