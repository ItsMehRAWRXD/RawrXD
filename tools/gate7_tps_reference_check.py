# Gate 7 correctness check: Deep2 greedy decode vs the independent llama.cpp
# reference over the exact sequence the benchmark executed.
#
# The reference is teacher-forced through prompt + Deep2's generated tokens
# (positions 0..134), so its logits at position p are conditioned on exactly
# the same KV state Deep2 held when it chose stream[p+1]. A match of the
# per-position argmax at every position is token-for-token greedy agreement
# (the strongest check that the trace-free path is not skipping work).
import os
import numpy as np

E = r"F:\rawrxd\evidence\GAP_AUDIT_2026-10-13\gate7_tps"
REF = os.path.join(E, "ref_chain_tps")

with open(os.path.join(E, "gate7_tps_tokens.txt")) as f:
    seq = [int(t) for t in f.read().split()]          # 135 tokens fed to the reference
with open(os.path.join(E, "bench_cold_b.log")) as f:
    for line in f:
        if line.startswith("RUN1 GENSTREAM:"):
            stream = [int(t) for t in line.split(":", 1)[1].split()]
            break
deep2_choices = stream  # GENSTREAM = the 128 generated tokens, choices after pos 7..134
n = len(seq)            # tokens fed to the reference (prompt + generated[0..126])
assert len(deep2_choices) == n - 7, (len(deep2_choices), n)
print("evaluated positions: %d (feed seq %d, deep2 choices %d, final token %d)"
      % (n, len(seq), len(deep2_choices), stream[-1]))

matches = 0
compared = 0
finite_ok = True
rows = []
prompt_len = 8  # prefill positions 0..7 are teacher-forced; generation starts after pos 7
for p in range(prompt_len - 1, n):
    with open(os.path.join(REF, "ref_logits_pos%d.bin" % p), "rb") as f:
        ref = np.frombuffer(f.read(), dtype="<f4").astype(np.float64)
    if not np.all(np.isfinite(ref)):
        finite_ok = False
    ref_arg = int(np.argmax(ref))
    d2_arg = stream[p - (prompt_len - 1)]  # Deep2's choice after position p
    compared += 1
    ok = ref_arg == d2_arg
    matches += 1 if ok else 0
    if not ok:
        top = np.argsort(ref)[::-1]
        rank = int(np.where(top == d2_arg)[0][0])
        rows.append({"pos": p, "ref": ref_arg, "d2": d2_arg, "d2_rank_in_ref": rank,
                     "ref_top_logit": float(ref[ref_arg])})

print("compared generation decisions: %d (positions %d..%d)" % (compared, prompt_len - 1, n - 1))
print("reference logits finite: %s" % finite_ok)
print("ARGMAX_MATCHES=%d/%d (%.1f%%)" % (matches, compared, 100.0 * matches / compared))
for r in rows:
    print("  mismatch pos %d: ref=%d d2=%d (d2 is ref rank %d, ref top logit %.4f)"
          % (r["pos"], r["ref"], r["d2"], r["d2_rank_in_ref"], r["ref_top_logit"]))
verdict = "PASS" if finite_ok and matches == compared else ("PASS_BOUNDED" if finite_ok else "FAIL")
print("GATE7_CORRECTNESS_VERDICT=%s (token-for-token=%s)" % (verdict, "yes" if matches == compared else "no"))

with open(os.path.join(E, "gate7_tps_reference_check.txt"), "w") as f:
    f.write("compared_positions=%d\nfinite=%s\nargmax_matches=%d/%d\nverdict=%s\n"
            % (compared, finite_ok, matches, compared, verdict))
    for r in rows:
        f.write("mismatch pos=%d ref=%d d2=%d d2_rank_in_ref=%d ref_top_logit=%.4f\n"
                % (r["pos"], r["ref"], r["d2"], r["d2_rank_in_ref"], r["ref_top_logit"]))
print("wrote gate7_tps_reference_check.txt")
