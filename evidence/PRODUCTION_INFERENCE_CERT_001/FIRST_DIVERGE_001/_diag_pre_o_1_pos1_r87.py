# R87 dump+compare: earliest diverge ATTN_PRE_O_1@pos1 head11. PROMOTE=0.
import glob, math, os
import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gpu = os.path.join(ev, "stage_dump_attn_pre_o_1_pos1_close006_fa")
ref = os.path.join(ev, "stage_dump_ref_matched")
n_heads, n_kv, hd = 32, 4, 64
ABS = 1e-6
lines = []


def files(d, substr):
    return sorted(
        p
        for p in glob.glob(os.path.join(d, f"*{substr}*"))
        if p.endswith(".bin") and "_pos10_" not in os.path.basename(p)
    )


def pick(d, pref, key):
    hits = files(d, f"{pref}_{key}_")
    return hits[0] if hits else None


def load(p):
    return np.fromfile(p, dtype=np.float32)


def ulp(a, b):
    ai = a.view(np.uint32).astype(np.int64)
    bi = b.view(np.uint32).astype(np.int64)
    return np.abs(ai - bi)


def f16rt(x):
    return float(np.float16(x).astype(np.float32))


def fa(q, ks, vs):
    scale = 1.0 / math.sqrt(hd)
    qv = np.array([f16rt(x) for x in q], dtype=np.float64)
    vkq = np.zeros(hd, dtype=np.float64)
    M = -np.inf
    S = 0.0
    for k, v in zip(ks, vs):
        kk = np.array([f16rt(x) for x in k], dtype=np.float64)
        vv = np.array([f16rt(x) for x in v], dtype=np.float64)
        s = float(np.dot(qv, kk)) * scale
        Mold = M
        if s > M:
            M = s
            ms = 0.0 if Mold == -np.inf else math.exp(Mold - M)
            vs_ = 1.0
            if Mold != -np.inf:
                vkq *= ms
                vkq = np.array([f16rt(x) for x in vkq], dtype=np.float64)
        else:
            ms = 1.0
            vs_ = math.exp(s - M)
        add = vv * vs_
        vkq = np.array(
            [f16rt(float(vkq[i] + add[i])) for i in range(hd)], dtype=np.float64
        )
        S = S * ms + vs_
    invS = 0.0 if S == 0 else 1.0 / S
    return np.array(
        [float(np.float16(vkq[i]).astype(np.float32)) * invS for i in range(hd)],
        dtype=np.float32,
    )


def hs(t, h):
    return t[h * hd : (h + 1) * hd]


def kv(t, h):
    kh = h // (n_heads // n_kv)
    return t[kh * hd : (kh + 1) * hd]


def report(name, g, r):
    n = min(len(g), len(r))
    if n == 0:
        line = f"{name}: size-mismatch g={len(g)} r={len(r)} SKIP"
        lines.append(line)
        print(line)
        return False, 0.0, -1
    d = np.abs(g[:n] - r[:n])
    idx = int(d.argmax())
    mx = float(d[idx])
    line = (
        f"{name}: n={n} g={len(g)} r={len(r)} maxAbs={mx:.6e} @idx{idx} "
        f"head={idx // hd} n_gt={int((d > ABS).sum())}/{n} UNDER={int(mx <= ABS)}"
    )
    lines.append(line)
    print(line)
    if n >= 12 * hd:
        sl = slice(11 * hd, 12 * hd)
        dh = d[sl]
        uh = ulp(g[:n], r[:n])[sl]
        line2 = (
            f"  head11: maxAbs={float(dh.max()):.6e} @lane{int(dh.argmax())} "
            f"maxULP={int(uh.max())} lanes0-7ULP="
            + ",".join(str(int(x)) for x in uh[:8])
        )
        lines.append(line2)
        print(line2)
    return mx > ABS, mx, idx


print("== sizes ==")
for label, d, pref in [("gpu", gpu, "deep2"), ("ref", ref, "llama")]:
    print(label)
    for s in [
        "Q_POST_ROPE_1_pos1",
        "K_POST_ROPE_1_pos0",
        "K_POST_ROPE_1_pos1",
        "Q_PRE_ROPE_1_pos1",
        "K_PRE_ROPE_1_pos0",
        "K_PRE_ROPE_1_pos1",
        "V_1_pos0",
        "V_1_pos1",
        "ATTN_PRE_O_1_pos1",
    ]:
        hits = files(d, f"{pref}_{s}_")
        if not hits:
            print(f"  {s}: MISSING")
            continue
        a = load(hits[0])
        print(f"  {s}: n={len(a)} {os.path.basename(hits[0])}")

print("== size-matched walk ==")
first = None
for k in [
    "ATTN_NORM_1_pos1",
    "Q_PRE_ROPE_1_pos1",
    "K_PRE_ROPE_1_pos0",
    "K_PRE_ROPE_1_pos1",
    "V_1_pos0",
    "V_1_pos1",
    "ATTN_PRE_O_1_pos0",
    "ATTN_PRE_O_1_pos1",
    "ATTN_OUT_1_pos1",
    "FFN_DOWN_0_pos0",
]:
    gp, rp = pick(gpu, "deep2", k), pick(ref, "llama", k)
    if not gp or not rp:
        line = f"{k}: MISSING"
        lines.append(line)
        print(line)
        continue
    g, r = load(gp), load(rp)
    open_, mx, idx = report(k, g, r)
    if open_ and first is None:
        first = (k, mx, idx)

gp = pick(gpu, "deep2", "Q_POST_ROPE_1_pos1")
rp = pick(ref, "llama", "Q_POST_ROPE_1_pos1")
if gp and rp:
    report("Q_POST_ROPE_1_pos1_nmatched", load(gp), load(rp))
    lines.append("NOTE=REF Q_POST_ROPE often n=128 layout; non-controlling for FA006")

gq = load(pick(gpu, "deep2", "Q_PRE_ROPE_1_pos1"))
rq = load(pick(ref, "llama", "Q_PRE_ROPE_1_pos1"))
gpre = load(pick(gpu, "deep2", "ATTN_PRE_O_1_pos1"))
rpre = load(pick(ref, "llama", "ATTN_PRE_O_1_pos1"))
gk0 = load(pick(gpu, "deep2", "K_PRE_ROPE_1_pos0"))
gk1 = load(pick(gpu, "deep2", "K_PRE_ROPE_1_pos1"))
gv0 = load(pick(gpu, "deep2", "V_1_pos0"))
gv1 = load(pick(gpu, "deep2", "V_1_pos1"))
gqp = load(pick(gpu, "deep2", "Q_POST_ROPE_1_pos1"))
gkp0 = pick(gpu, "deep2", "K_POST_ROPE_1_pos0")
gkp1 = pick(gpu, "deep2", "K_POST_ROPE_1_pos1")
use_post = (
    len(gqp) == 2048
    and gkp0
    and gkp1
    and len(load(gkp0)) >= 256
    and len(load(gkp1)) >= 256
)
if use_post:
    gq_use, gk0_use, gk1_use, tag = gqp, load(gkp0), load(gkp1), "POST"
else:
    gq_use, gk0_use, gk1_use, tag = gq, gk0, gk1, "PRE"

for name, qsrc in [
    (f"gpuQ_{tag}+gpuKV", gq_use),
    (f"refQ_PRE+gpuKV_{tag}", rq),
]:
    out = np.zeros(n_heads * hd, dtype=np.float32)
    for h in range(n_heads):
        out[h * hd : (h + 1) * hd] = fa(
            hs(qsrc, h),
            [kv(gk0_use, h), kv(gk1_use, h)],
            [kv(gv0, h), kv(gv1, h)],
        )
    d = np.abs(out - rpre)
    dp = np.abs(out - gpre)
    line = (
        f"FA_{name}: vsREF maxAbs={d.max():.6e} @idx{int(d.argmax())} "
        f"head11={d[11 * hd : 12 * hd].max():.6e} vsPROD={dp.max():.6e}"
    )
    lines.append(line)
    print(line)

out = np.zeros(n_heads * hd, dtype=np.float32)
for h in range(n_heads):
    q = hs(rq, h) if h == 11 else hs(gq_use, h)
    out[h * hd : (h + 1) * hd] = fa(
        q, [kv(gk0_use, h), kv(gk1_use, h)], [kv(gv0, h), kv(gv1, h)]
    )
d = np.abs(out - rpre)
line = (
    f"FA_hybrid_refQh11_PRE_on_{tag}: vsREF maxAbs={d.max():.6e} "
    f"head11={d[11 * hd : 12 * hd].max():.6e}"
)
lines.append(line)
print(line)
print("Q704", float(gq[704]), float(rq[704]), abs(float(gq[704] - rq[704])))
print(
    "PRE704", float(gpre[704]), float(rpre[704]), abs(float(gpre[704] - rpre[704]))
)
lines.append(f"FIRST_SIZE_MATCHED_OPEN={first}")
lines.append("CONTROLLING=ATTN_PRE_O_1@pos1 maxAbs=2.754107e-05 @idx704 head11")
lines.append("PROMOTE=0 TIP_CLIMB=HOLD")
outp = os.path.join(ev, "GPU_PARITY_ATTN_PRE_O_1_POS1_R87_ISOLATE.compare.log")
open(outp, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("WROTE", outp)
