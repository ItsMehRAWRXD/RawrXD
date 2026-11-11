# Supporting analysis for the Gate-5 disagreements: for each argmax disagreement,
# locate Deep2's argmax inside the reference's own ranking. A genuine numerical
# boundary flip shows d2's argmax == ref's top-2 (the reference's own margin
# between top1 and top2 is smaller than the measured elementwise error).
import json
import os
import numpy as np

E = r"F:\rawrxd\evidence\GAP_AUDIT_2026-10-13\gate5"
N = 129

rows = []
for p in range(N):
    with open(os.path.join(E, "ref_head", "ref_logits_pos%d.bin" % p), "rb") as f:
        ref = np.frombuffer(f.read(), dtype="<f4").astype(np.float64)
    with open(os.path.join(E, "d2_gpu_head", "d2_logits_pos%d.bin" % p), "rb") as f:
        gpu = np.frombuffer(f.read(), dtype="<f4").astype(np.float64)
    order = np.argsort(ref)[::-1]
    rank_of = np.empty(ref.size, dtype=np.int64)
    rank_of[order] = np.arange(ref.size)
    arg_r, arg_g = int(np.argmax(ref)), int(np.argmax(gpu))
    if arg_r == arg_g:
        continue
    margin = float(ref[order[0]] - ref[order[1]])
    rows.append({
        "pos": p,
        "ref_top1": arg_r, "ref_top2": int(order[1]), "ref_top3": int(order[2]),
        "gpu_argmax": arg_g,
        "gpu_argmax_rank_in_ref": int(rank_of[arg_g]),
        "ref_margin_top1_top2": margin,
        "maxabs": float(np.max(np.abs(ref - gpu))),
    })

print("GPU-vs-reference argmax disagreements: %d" % len(rows))
print("%-5s %-9s %-9s %-9s %-11s %-9s %-9s %-8s" % ("pos", "ref_top1", "ref_top2", "gpu_arg", "rank_in_ref", "margin", "maxabs", "flip_ok"))
ok = 0
for r in rows:
    flip = r["gpu_argmax"] == r["ref_top2"] and r["ref_margin_top1_top2"] < r["maxabs"]
    ok += 1 if flip else 0
    print("%-5d %-9d %-9d %-9d %-11d %-9.4f %-9.4f %-8s"
          % (r["pos"], r["ref_top1"], r["ref_top2"], r["gpu_argmax"],
             r["gpu_argmax_rank_in_ref"], r["ref_margin_top1_top2"], r["maxabs"], "YES" if flip else "no"))
print("disagreements where gpu argmax is exactly the reference's top-2 inside the error bound: %d/%d" % (ok, len(rows)))

with open(os.path.join(E, "gate5_disagreement_decomposition.json"), "w") as f:
    json.dump(rows, f, indent=1)
print("wrote gate5_disagreement_decomposition.json")
