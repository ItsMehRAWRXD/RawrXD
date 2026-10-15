#!/usr/bin/env python3
"""
DEEP2_FFN_ACCUMULATION_PARITY_001
Find the FIRST divergent tensor at position 10 across all layers, then
capture the full FFN chain at that layer with dtype/precision detail.
"""
import os
import numpy as np

D2 = r"F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone"
REF = r"F:\rawrxd\evidence\deep2_gate_a\ref_intermediate_v2"

def load_bin(p, dtype='<f4'):
    with open(p, 'rb') as f:
        return np.frombuffer(f.read(), dtype=dtype).astype(np.float64)

def build_trace(pos):
    m = {}
    with open(os.path.join(D2, f"d2_trace_pos{pos}.txt")) as f:
        for line in f:
            if line.startswith('blk='):
                p = line.strip().split()
                m[(int(p[0].split('=')[1]), p[3].split('=')[1])] = (int(p[1].split('=')[1]), p[4].split('=')[1])
    return m

def d2_tensor(pos, layer, name):
    blk = 999 if layer < 0 else layer
    trace = build_trace(pos)
    if (layer, name) not in trace:
        return None
    pc = trace[(layer, name)][0]
    path = os.path.join(D2, f"d2_pos{pos}_blk{blk}_pc{pc}_{name}.bin")
    if not os.path.exists(path):
        nm = ''.join(c if (c.isalnum() or c in '-_.') else '_' for c in name)
        path = os.path.join(D2, f"d2_pos{pos}_blk{blk}_pc{pc}_{nm}.bin")
    return load_bin(path) if os.path.exists(path) else None

def ref_tensor(pos, layer, name, stage=1):
    base = os.path.join(REF, f"ref_pos{pos}_layer{layer}_{name}_layer{layer}")
    cand = base + ("" if stage == 0 else f"_stage{stage}") + ".bin"
    if not os.path.exists(cand) and stage != 0:
        cand = base + ".bin"
    return load_bin(cand) if os.path.exists(cand) else None

def metrics(a, b):
    diff = a - b
    denom = np.linalg.norm(a) * np.linalg.norm(b)
    return {
        'cosine': float(np.dot(a, b) / denom) if denom > 0 else 0.0,
        'rmse': float(np.sqrt(np.mean(diff ** 2))),
        'maxabs': float(np.max(np.abs(diff))),
        'n': a.shape[0],
    }

ORDER = ['attn_norm', 'q', 'k', 'v', 'attn_out', 'ffn_norm', 'gate', 'up', 'swiglu', 'ffn_out']

print("=" * 72)
print("STEP 1: find FIRST divergent tensor at position 10 (all 28 layers)")
print("=" * 72)
first_div = None
for layer in range(28):
    for name in ORDER:
        d2 = d2_tensor(10, layer, name)
        ref = ref_tensor(10, layer, name, 1)
        if d2 is None or ref is None or d2.shape != ref.shape:
            continue
        m = metrics(d2, ref)
        if m['cosine'] < 0.999 and first_div is None:
            first_div = (layer, name, m)
            print(f"  FIRST DIVERGENT: layer={layer} op={name} cos={m['cosine']:.6f} "
                  f"rmse={m['rmse']:.6e} maxabs={m['maxabs']:.6e}")
            break
    if first_div:
        break

# Also print per-layer minimum to show the trend
print("\nPer-layer min cosine at position 10:")
mins = []
for layer in range(28):
    lo = 1.0; lo_name = ''
    for name in ORDER:
        d2 = d2_tensor(10, layer, name)
        ref = ref_tensor(10, layer, name, 1)
        if d2 is None or ref is None or d2.shape != ref.shape:
            continue
        m = metrics(d2, ref)
        if m['cosine'] < lo:
            lo = m['cosine']; lo_name = name
    mins.append((layer, lo, lo_name))
    flag = '  <-- below 0.999' if lo < 0.999 else ''
    print(f"  L{layer:2d} min={lo:.6f} ({lo_name}){flag}")

print("\n" + "=" * 72)
print("STEP 2: full FFN chain capture at first divergent layer / position 10")
print("=" * 72)
div_layer = first_div[0] if first_div else 22
print(f"layer = {div_layer}, position = 10")

CHAIN = ['ffn_norm', 'gate', 'up', 'swiglu', 'ffn_out']
results = []
for name in CHAIN:
    d2 = d2_tensor(10, div_layer, name)
    ref = ref_tensor(10, div_layer, name, 1)
    if d2 is None or ref is None:
        print(f"  {name:10s}: MISSING (d2={d2 is not None}, ref={ref is not None})")
        continue
    m = metrics(d2, ref)
    results.append((name, m))
    print(f"  {name:10s}: cos={m['cosine']:.8f}  rmse={m['rmse']:.6e}  "
          f"maxabs={m['maxabs']:.6e}  n={m['n']}  dtype=f32")

# Also capture position 19 (worst) for comparison
print("\n" + "=" * 72)
print("STEP 3: same FFN chain at position 19 (worst cosine)")
print("=" * 72)
for name in CHAIN:
    d2 = d2_tensor(19, div_layer, name)
    ref = ref_tensor(19, div_layer, name, 1)
    if d2 is None or ref is None:
        continue
    m = metrics(d2, ref)
    print(f"  {name:10s}: cos={m['cosine']:.8f}  rmse={m['rmse']:.6e}  maxabs={m['maxabs']:.6e}")

# Step 4: precision analysis - is the error zero-mean noise or systematic?
print("\n" + "=" * 72)
print("STEP 4: error characterization (zero-mean noise vs systematic bias)")
print("=" * 72)
for name in ['ffn_norm', 'gate', 'up', 'swiglu', 'ffn_out']:
    d2 = d2_tensor(10, div_layer, name)
    ref = ref_tensor(10, div_layer, name, 1)
    if d2 is None or ref is None or d2.shape != ref.shape:
        continue
    diff = d2 - ref
    scale = np.max(np.abs(ref)) if np.max(np.abs(ref)) > 0 else 1.0
    print(f"  {name:10s}: err_mean={np.mean(diff):+.3e}  err_std={np.std(diff):.3e}  "
          f"max_abs_ref={scale:.3e}  rel_err={np.max(np.abs(diff))/scale:.3e}")
    # correlation of error with magnitude
    if np.std(ref) > 0:
        corr = np.corrcoef(diff, ref)[0, 1]
        print(f"               corr(err, ref)={corr:+.4f}")

print("\n" + "=" * 72)
print("VERDICT")
print("=" * 72)
if first_div:
    l, n, m = first_div
    print(f"first_divergent_layer = {l}")
    print(f"first_divergent_op = {n}")
    print(f"tensor_shape = {m['n']}")
    print(f"quant_type = Q2_K (gate/up) / Q3_K (ffn_down) + f32 norm")
    print(f"cosine = {m['cosine']:.8f}")
    print(f"max_abs = {m['maxabs']:.6e}")
    print(f"rms = {m['rmse']:.6e}")
