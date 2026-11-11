# final_gate.py -- post-bias-fix Deep2 parity vs real llama.cpp at position 0.
import os
import numpy as np

BASE = r"F:\rawrxd\evidence\PARITY_2026-10-13"
LLAMA = np.fromfile(os.path.join(BASE, "llama_truth", "ref_logits_pos0.bin"),
                    dtype="<f4").astype(np.float64)
D2_CPU = np.fromfile(os.path.join(BASE, "postbiasfix", "d2post_cpu.pos0.f32"),
                     dtype="<f4").astype(np.float64)
D2_GPU = np.fromfile(os.path.join(BASE, "postbiasfix", "d2post_gpu.pos0.f32"),
                     dtype="<f4").astype(np.float64)
D2_OLD = np.fromfile(os.path.join(BASE, "qwen_d2_750.pos0.f32"),
                     dtype="<f4").astype(np.float64)
REF = np.fromfile(os.path.join(BASE, "reftied750.pos0.LOGITS.f32"),
                  dtype="<f4").astype(np.float64)


def report(tag, X):
    d = X - LLAMA
    cos = float(X @ LLAMA / (np.linalg.norm(X) * np.linalg.norm(LLAMA)))
    rmse = float(np.sqrt(np.mean(d * d)))
    mx = float(np.abs(d).max())
    rel = float(np.linalg.norm(d) / np.linalg.norm(LLAMA))
    print(f"  {tag:34s} cos={cos:9.6f} relL2={rel:.6f} rmse={rmse:9.4g} "
          f"maxabs={mx:8.4g} argmax={int(np.argmax(X))} "
          f"{'MATCH' if int(np.argmax(X)) == int(np.argmax(LLAMA)) else 'DIFFER'}")


print("PARITY GATE  pos=0 token=750  qwen2.5-coder_1.5b-base.gguf")
print(f"  llama.cpp argmax = {int(np.argmax(LLAMA))}  "
       f"(self-consistent: 1-token vs 7-token maxabs=0.000000)\n")
print("  Deep2 vs llama.cpp:")
report("Deep2 POST-BIAS-FIX CPU", D2_CPU)
report("Deep2 POST-BIAS-FIX GPU", D2_GPU)
report("Deep2 PRE-BIAS-FIX (old log)", D2_OLD)
print("\n  exact numpy reference vs llama.cpp (protocol offset):")
report("numpy reference (exact arithmetic)", REF)
print(f"\n  Deep2 CPU vs GPU (internal consistency): "
      f"maxabs={float(np.abs(D2_CPU - D2_GPU).max()):.6g}")
