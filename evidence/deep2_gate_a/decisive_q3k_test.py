#!/usr/bin/env python3
"""
Decisive experiment: does Deep2's Q3_K CPU integer-dot kernel match the
llama.cpp reference better than the current GPU-mode run?

Compares:
  A = Deep2 GPU-mode run (d2_gpu_milestone)      <-- current
  B = Deep2 CPU-mode run (d2_cpu_q3k, force_cpu) <-- integer-dot kernel for ALL
  R = llama.cpp reference (ref_intermediate_v2)
"""
import os
import numpy as np

GPU = r"F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone"
CPU = r"F:\rawrxd\evidence\deep2_gate_a\d2_cpu_q3k"
REF = r"F:\rawrxd\evidence\deep2_gate_a\ref_intermediate_v2"

def load_bin(p):
    with open(p, 'rb') as f:
        return np.frombuffer(f.read(), dtype='<f4').astype(np.float64)

def build_trace(base, pos):
    m = {}
    p = os.path.join(base, f"d2_trace_pos{pos}.txt")
    if not os.path.exists(p):
        return m
    with open(p) as f:
        for line in f:
            if line.startswith('blk='):
                q = line.strip().split()
                m[(int(q[0].split('=')[1]), q[3].split('=')[1])] = int(q[1].split('=')[1])
    return m

def d2_tensor(base, pos, layer, name):
    blk = 999 if layer < 0 else layer
    tr = build_trace(base, pos)
    if (layer, name) not in tr:
        return None
    pc = tr[(layer, name)]
    path = os.path.join(base, f"d2_pos{pos}_blk{blk}_pc{pc}_{name}.bin")
    return load_bin(path) if os.path.exists(path) else None

def ref_tensor(pos, layer, name, stage=1):
    b = os.path.join(REF, f"ref_pos{pos}_layer{layer}_{name}_layer{layer}")
    c = b + ("" if stage == 0 else f"_stage{stage}") + ".bin"
    if not os.path.exists(c) and stage != 0:
        c = b + ".bin"
    return load_bin(c) if os.path.exists(c) else None

def cos(a, b):
    if a is None or b is None or a.shape != b.shape:
        return None
    d = np.linalg.norm(a) * np.linalg.norm(b)
    return float(np.dot(a, b) / d) if d > 0 else 0.0

Q3K_OPS = ['v', 'attn_out', 'ffn_out']  # Q3_K-driven tensors
Q2K_OPS = ['q', 'k', 'gate', 'up']     # Q2_K-driven tensors

POS = 10
print("=" * 74)
print("DECISIVE: Q3_K-driven tensors at position 10 - GPU-mode vs CPU-mode vs llama.cpp")
print("=" * 74)
print(f"{'layer':>5} {'op':<10} {'GPUvsREF':>10} {'CPUvsREF':>10} {'CPUvsGPU':>10}  winner")
worse = 0
for layer in range(28):
    for op in Q3K_OPS:
        g = d2_tensor(GPU, POS, layer, op)
        c = d2_tensor(CPU, POS, layer, op)
        r = ref_tensor(POS, layer, op, 1)
        cg, cc, cgc = cos(g, r), cos(c, r), cos(c, g)
        if cg is None or cc is None:
            continue
        winner = 'CPU' if cc > cg + 1e-9 else ('GPU' if cg > cc + 1e-9 else 'tie')
        if winner == 'CPU':
            worse += 1
        mark = ''
        if cg < 0.999:
            mark = ' <-- GPU below 0.999'
            if cc >= 0.999:
                mark += ', CPU PASSES'
        print(f"{layer:>5} {op:<10} {cg:>10.6f} {cc:>10.6f} {cgc:>10.6f}  {winner}{mark}")

print(f"\nLayers where CPU-mode (pure integer-dot) beats GPU-mode: {worse}")

print("\n" + "=" * 74)
print("Q2_K tensors (gate/up) for comparison - these run on GPU shader")
print("=" * 74)
for layer in range(28):
    for op in Q2K_OPS:
        g = d2_tensor(GPU, POS, layer, op)
        c = d2_tensor(CPU, POS, layer, op)
        r = ref_tensor(POS, layer, op, 1)
        cg, cc = cos(g, r), cos(c, r)
        if cg is None or cc is None:
            continue
        if layer < 3 or cg < 0.999:
            print(f"{layer:>5} {op:<10} GPU={cg:.6f} CPU={cc:.6f}")

print("\n" + "=" * 74)
print("Final logits")
print("=" * 74)
for base, label in [(GPU, 'GPU-mode'), (CPU, 'CPU-mode')]:
    d2 = load_bin(os.path.join(base, f"d2_logits_pos{split.txt()[0] if False else 10}.bin"))
    r = load_bin(os.path.join(REF, "ref_logits_pos10.bin"))
    print(f"  {label} pos10 logits cos = {cos(d2, r):.8f}")
