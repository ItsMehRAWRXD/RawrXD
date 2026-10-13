# D2 verification: full-logit parity of the BATCHED executor path vs the
# SERIAL (one-submit-per-dot) path over 135 teacher-forced positions.
# Batched : tools/deep2_bench_tps.exe --dump-logits (dot groups queued)
# Serial  : tools/deep2_parity_trace.exe --gpu --outdir (SetOpTrace on =>
#           grouping disabled; --gpu is REQUIRED: without it the harness pins
#           the CPU path and the comparison measures GPU-vs-CPU, not batching)
# Same 135 token ids, same model, same device. A same-binary control
# (deep2_bench_tps --no-batch --dump-logits) is also compared when present.
import json
import os
import numpy as np

E = r"F:\rawrxd\evidence\GAP_AUDIT_2026-10-13\gate7_tps"
N = 135
VOCAB = 32000
BATCHED = "d2_batched_logits"
SERIAL = "d2_serial_gpu_logits"          # GPU-native serial (parity harness)
NOBATCH = "d2_nobatch_logits"            # same-binary control, if present


def load(d, p):
    with open(os.path.join(E, d, "d2_logits_pos%d.bin" % p), "rb") as f:
        return np.frombuffer(f.read(), dtype="<f4")


def compare(dir_a, dir_b):
    identical = argmax = 0
    worst_cos, worst_abs, worst_rmse = 1.0, 0.0, 0.0
    for p in range(N):
        a, b = load(dir_a, p), load(dir_b, p)
        assert a.size == b.size == VOCAB, (p, a.size, b.size)
        same = a.tobytes() == b.tobytes()
        identical += 1 if same else 0
        argmax += 1 if int(np.argmax(a)) == int(np.argmax(b)) else 0
        if not same:
            d = a.astype(np.float64) - b.astype(np.float64)
            worst_abs = max(worst_abs, float(np.max(np.abs(d))))
            worst_rmse = max(worst_rmse, float(np.sqrt(np.mean(d * d))))
            worst_cos = min(worst_cos, float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))))
    return {"bit_identical": identical, "argmax_match": argmax,
            "worst_cos": worst_cos, "worst_maxabs": worst_abs, "worst_rmse": worst_rmse}


res = {"positions": N}
res["batched_vs_serial_gpu"] = compare(BATCHED, SERIAL)
if all(os.path.exists(os.path.join(E, NOBATCH, "d2_logits_pos%d.bin" % p)) for p in range(N)):
    res["batched_vs_same_binary_nobatch"] = compare(BATCHED, NOBATCH)

print("positions=%d" % N)
for k, v in res.items():
    if k == "positions":
        continue
    print("%s: bit_identical=%d/%d argmax_match=%d/%d worst_cos=%.12f worst_maxabs=%.9g worst_rmse=%.9g"
          % (k, v["bit_identical"], N, v["argmax_match"], N, v["worst_cos"], v["worst_maxabs"], v["worst_rmse"]))
verdict = "PASS" if all(v["bit_identical"] == N for k, v in res.items() if k != "positions") else "FAIL"
print("D2_PARITY_VERDICT=%s" % verdict)

with open(os.path.join(E, "gate7_d2_batched_vs_serial_logits.txt"), "w") as f:
    f.write("positions=%d\n" % N)
    for k, v in res.items():
        if k == "positions":
            continue
        f.write("%s: bit_identical=%d/%d argmax_match=%d/%d worst_cos=%.12f worst_maxabs=%.9g worst_rmse=%.9g\n"
                % (k, v["bit_identical"], N, v["argmax_match"], N, v["worst_cos"], v["worst_maxabs"], v["worst_rmse"]))
    f.write("verdict=%s\n" % verdict)
with open(os.path.join(E, "gate7_d2_batched_vs_serial_logits.json"), "w") as f:
    json.dump(dict(res, verdict=verdict), f, indent=1)
print("wrote gate7_d2_batched_vs_serial_logits.txt/.json")
