# gate1b_parity_compare.py -- aligned forward-parity comparator.
#
# Compares, per position, Deep2's dumped logits (parity.pos<p>.f32/.json)
# against the llama.cpp reference (ref.pos<p>.f32/.json): identical GGUF,
# identical token-id sequence, identical positions, identical KV history.
# Emits the PARITY_* receipt block per position.
import json
import os
import sys
import numpy as np

OUTDIR = sys.argv[1] if len(sys.argv) > 1 else r"F:\rawrxd\evidence\PARITY_2026-10-13"

sha = open(os.path.join(OUTDIR, 'model_sha256.txt')).read().strip()
positions = [int(x) for x in open(os.path.join(OUTDIR, 'positions.txt')).read().split(',') if x.strip()]

print(f'PARITY_MODEL_SHA256={sha}')
for p in positions:
    d = np.fromfile(os.path.join(OUTDIR, f'parity.pos{p}.f32'), dtype='<f4')
    r = np.fromfile(os.path.join(OUTDIR, f'ref.pos{p}.f32'), dtype='<f4')
    dj = json.load(open(os.path.join(OUTDIR, f'parity.pos{p}.json')))
    rj = json.load(open(os.path.join(OUTDIR, f'ref.pos{p}.json')))
    n = min(d.shape[0], r.shape[0])
    d, r = d[:n], r[:n]
    cos = float(np.dot(d, r) / (np.linalg.norm(d) * np.linalg.norm(r) + 1e-30))
    maxabs = float(np.max(np.abs(d - r)))
    rmse = float(np.sqrt(np.mean((d - r) ** 2)))
    t10d = set(dj['top10'])
    t10r = set(rj['top10'])
    overlap = len(t10d & t10r)
    d_nf = dj['nonfinite']
    print(f'PARITY_TOKEN_ID={dj["token_id"]}')
    print(f'PARITY_POSITION={p}')
    print(f'PARITY_LOGIT_COUNT={dj["logits"]} (ref={rj["logits"]})')
    print(f'DEEP2_ARGMAX={dj["argmax"]}')
    print(f'REFERENCE_ARGMAX={rj["argmax"]}')
    print(f'ARGMAX_MATCH={"yes" if dj["argmax"] == rj["argmax"] else "no"}')
    print(f'COSINE={cos:.6f}')
    print(f'MAX_ABS={maxabs:.4f}')
    print(f'RMSE={rmse:.4f}')
    print(f'TOP10_OVERLAP={overlap}/10')
    print(f'NONFINITE_deep2={d_nf} NONFINITE_ref={rj["nonfinite"]}')
    print(f'GPU_CALLS={dj["gpu_calls"]} CPU_CALLS={dj["cpu_calls"]}')
    print('---')
