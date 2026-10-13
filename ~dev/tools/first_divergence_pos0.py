# first_divergence_pos0.py -- locate Deep2's first divergent operator against
# the validated numpy reference at position 0, token 750.
import os
import numpy as np

BASE = r"F:\rawrxd\evidence\PARITY_2026-10-13"
REF = os.path.join(BASE, "reftied750.pos0")
D2 = os.path.join(BASE, "d2q750 ")          # note the trailing space


def rd(path):
    return np.fromfile(path, dtype="<f4").astype(np.float64)


def cmp(a, b):
    d = a - b
    return (float(np.linalg.norm(d)),
            float(np.linalg.norm(d) / max(np.linalg.norm(b), 1e-30)),
            float(a @ b / (np.linalg.norm(a) * np.linalg.norm(b))))


print("FIRST-DIVERGENCE SCAN  pos=0 token=750 (Deep2 build: pre-bias-fix)")
print("  ref tensors are EXACT arithmetic; llama.cpp applies Q8_K activations,")
print("  so a small protocol-level offset vs reference is expected.\n")

# embedding -> first attention residual
emb = rd(REF + ".EMBED.f32")
r0a = rd(REF + ".ATTN_RESIDUAL.L0.f32")
d0a = rd(D2 + ".blk0.resid1.f32")
r0f = rd(REF + ".LAYER_RESIDUAL.L0.f32")
d0f = rd(D2 + ".blk0.resid2.f32")

for name, r, d in (("blk0 resid1 (attn)", r0a, d0a),
                   ("blk0 resid2 (ffn )", r0f, d0f)):
    n, rel, cs = cmp(d, r)
    print(f"  {name}: ref_L2={np.linalg.norm(r):10.5f} "
          f"d2_L2={np.linalg.norm(d):10.5f}  relL2={rel:.6f} cos={cs:.6f}")

print("\n  per-block relative L2 error (Deep2 vs reference):")
first = None
for blk in range(28):
    r1 = rd(f"{REF}.ATTN_RESIDUAL.L{blk}.f32")
    r2 = rd(f"{REF}.LAYER_RESIDUAL.L{blk}.f32")
    d1 = rd(f"{D2}.blk{blk}.resid1.f32")
    d2 = rd(f"{D2}.blk{blk}.resid2.f32")
    _, rel1, _ = cmp(d1, r1)
    _, rel2, _ = cmp(d2, r2)
    mark = ""
    if first is None and (rel1 > 0.02 or rel2 > 0.02):
        first = (blk, rel1, rel2)
        mark = "   <== FIRST >2% DIVERGENCE"
    if blk < 3 or (first and blk <= first[0] + 1) or blk > 25:
        print(f"    blk{blk:2d}: attn relL2={rel1:.6f}  ffn relL2={rel2:.6f}"
              f"  (ref L2: {np.linalg.norm(r1):9.3f} -> "
              f"{np.linalg.norm(r2):9.3f}){mark}")
if first:
    print(f"\n  FIRST_>2PCT_DIVERGENCE = block {first[0]} "
          f"(attn relL2={first[1]:.6f}, ffn relL2={first[2]:.6f})")
else:
    print("\n  no >2% divergence found")
