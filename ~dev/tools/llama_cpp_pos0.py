# llama_cpp_pos0.py -- decisive arbiter using the llama-cpp-python binding
# (real llama.cpp core, an entry path independent of both
# llama_dump_logits_teacher_forced.exe and llama-cli.exe).
#
# Evaluates exactly token 750 at position 0 with an empty KV cache and dumps
# the full 151936-element logit vector.
from llama_cpp import Llama
import numpy as np
import os

MODEL = r"F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf"
TOK = 750
BASE = r"F:\rawrxd\evidence\PARITY_2026-10-13"

llm = Llama(model_path=MODEL, n_ctx=8, n_batch=8, n_threads=8,
            n_gpu_layers=0, logits_all=True, vocab_only=False,
            verbose=False)

print("LOGITS_ALL", llm._logits_all, "N_VOCAB", llm.n_vocab())

llm.reset()
llm.eval([TOK])

sc_all = np.asarray(llm.scores, dtype=np.float32)
print("SCORES_SHAPE", sc_all.shape)
for r in range(sc_all.shape[0]):
    row = sc_all[r]
    if float(np.abs(row).max()) == 0.0:
        continue
    top = np.argsort(-row.astype(np.float64))[:10]
    print(f"  row {r}: argmax={int(np.argmax(row))} "
          f"min={row.min():.6g} max={row.max():.6g}")
    print(f"    TOP10=" + ",".join(f"{int(i)}:{float(row[i]):.6f}" for i in top))
