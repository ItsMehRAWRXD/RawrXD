# gate1b_forward_ref.py -- aligned reference harness (llama.cpp side).
#
# Produces, for the SAME GGUF + SAME token-id sequence + SAME positions:
#   ids.txt            - the token ids llama.cpp assigns to the prompt
#   positions.txt      - the target positions (0,1,2,15,63)
#   ref.pos<p>.f32     - raw float32 LE logits at position p (real llama.cpp)
#   ref.pos<p>.json    - per-position receipt (argmax, top10, nonfinite)
#
# Deterministic: CPU-only eval (n_gpu_layers=0), greedy ordering, fixed model.
import json
import os
import sys
import numpy as np
import llama_cpp

MODEL = sys.argv[1] if len(sys.argv) > 1 else r"F:\rawrxd\llama3.2-3b-Q2_K.gguf"
OUTDIR = sys.argv[2] if len(sys.argv) > 2 else r"F:\rawrxd\evidence\PARITY_2026-10-13"
POSITIONS = [0, 1, 2, 15, 63]

PROMPT = (
    '#include <cstdio>\nint add(int a, int b) {\n    return a - b;\n}\n'
    'int main() {\n    printf("%d\\n", add(2, 3));\n    return 0;\n}\n'
    '#include <cstdio>\nint add(int a, int b) {\n    return a - b;\n}\n'
    'int main() {\n    printf("%d\\n", add(2, 3));\n    return 0;\n}\n'
).encode('utf-8')

os.makedirs(OUTDIR, exist_ok=True)

ll = llama_cpp.Llama(MODEL, logits_all=True, n_ctx=4096, n_gpu_layers=0, seed=0,
                     n_batch=512, verbose=False)
ids = ll.tokenize(PROMPT, add_bos=True)
assert len(ids) >= 65, f'prompt too short: {len(ids)} tokens'
with open(os.path.join(OUTDIR, 'ids.txt'), 'w') as f:
    f.write(','.join(map(str, ids)))
with open(os.path.join(OUTDIR, 'positions.txt'), 'w') as f:
    f.write(','.join(map(str, POSITIONS)))

ll.reset()
ll.eval(ids)
scores = ll.scores
print('eval ok; ids=%d scores_shape=%s' % (len(ids), scores.shape))

for p in POSITIONS:
    lg = scores[p]
    lg = np.asarray(lg, dtype=np.float32)
    nonfinite = int((~np.isfinite(lg)).sum())
    top = int(np.argmax(lg))
    top10 = np.argsort(lg)[::-1][:10].astype(int).tolist()
    lg.astype('<f4').tofile(os.path.join(OUTDIR, f'ref.pos{p}.f32'))
    rec = {
        'engine': 'llama.cpp', 'model': os.path.basename(MODEL),
        'position': p, 'token_id': ids[p], 'argmax': top,
        'logits': int(lg.shape[0]), 'nonfinite': nonfinite, 'top10': top10,
        'gpu_calls': 0, 'cpu_calls': 'all (reference CPU path)',
    }
    with open(os.path.join(OUTDIR, f'ref.pos{p}.json'), 'w') as f:
        json.dump(rec, f)
    print(f'REF_RC position={p} token_id={ids[p]} argmax={top} logits={lg.shape[0]} nonfinite={nonfinite}')

# model provenance: sha256 of the model file
import hashlib
h = hashlib.sha256()
with open(MODEL, 'rb') as f:
    for chunk in iter(lambda: f.read(1 << 24), b''):
        h.update(chunk)
print('MODEL_SHA256=' + h.hexdigest())
with open(os.path.join(OUTDIR, 'model_sha256.txt'), 'w') as f:
    f.write(h.hexdigest() + '\n')
