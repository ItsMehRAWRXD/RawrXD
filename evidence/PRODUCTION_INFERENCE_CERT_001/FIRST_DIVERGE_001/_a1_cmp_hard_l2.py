import os, glob, struct, hashlib
from datetime import datetime

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gpu = os.path.join(ev, "stage_dump_q4kq8k_spv")
ref = os.path.join(ev, "stage_dump_ref_matched")
gpu_old = os.path.join(ev, "stage_dump_vkspv_f28f")
ABS, REL = 1e-4, 1e-3


def load(path):
    with open(path, "rb") as f:
        b = f.read()
    n = len(b) // 4
    return list(struct.unpack("<%df" % n, b))


def fnv(path):
    h = 0xCBF29CE484222325
    with open(path, "rb") as f:
        data = f.read()
    for c in data:
        h ^= c
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return f"{h:016x}"


def cmp_t(a, b):
    n = min(len(a), len(b))
    max_abs = 0.0
    max_rel = 0.0
    first = None
    fails = 0
    for i in range(n):
        ae = abs(a[i] - b[i])
        den = max(abs(a[i]), abs(b[i]))
        re = ae / den if den > 1e-20 else ae
        if ae > max_abs:
            max_abs = ae
        if re > max_rel:
            max_rel = re
        if ae > ABS and re > REL:
            fails += 1
            if first is None:
                first = i
    return n, max_abs, max_rel, first, fails


def pick(dirp, pat, pref=None):
    rs = sorted(glob.glob(os.path.join(dirp, pat)))
    if not rs:
        return None
    if pref:
        for c in rs:
            if pref in os.path.basename(c):
                return c
    # prefer earliest seq for llama duplicates
    return rs[0]


pairs = [
    ("PROMPT_EMBED", "deep2_PROMPT_EMBED_pos0_layer0_full_n2048_*.bin",
     "llama_PROMPT_EMBED_pos0_layer0_full_n2048_*.bin", "seq001"),
    ("ATTN_NORM_0", "deep2_ATTN_NORM_0_pos0_layer0_full_n2048_*.bin",
     "llama_ATTN_NORM_0_pos0_layer0_full_n2048_*.bin", "seq003"),
    ("V_0", "deep2_V_0_pos0_layer0_full_n256_*.bin",
     "llama_V_0_pos0_layer0_full_n256_*.bin", "seq011"),
    ("Q_PRE_ROPE_0", "deep2_Q_PRE_ROPE_0_pos0_layer0_full_n2048_*.bin",
     "llama_Q_PRE_ROPE_0_pos0_layer0_full_n2048_*.bin", "seq005"),
    ("K_PRE_ROPE_0", "deep2_K_PRE_ROPE_0_pos0_layer0_full_n256_*.bin",
     "llama_K_PRE_ROPE_0_pos0_layer0_full_n256_*.bin", "seq015"),
    ("ATTN_OUT_0", "deep2_ATTN_OUT_0_pos0_layer0_full_n2048_*.bin",
     "llama_ATTN_OUT_0_pos0_layer0_full_n2048_*.bin", "seq063"),
    ("FFN_NORM_0", "deep2_FFN_NORM_0_pos0_layer0_full_n2048_*.bin",
     "llama_FFN_NORM_0_pos0_layer0_full_n2048_*.bin", "seq067"),
    ("LAYER0_OUT", "deep2_LAYER0_OUT_pos0_layer0_full_n2048_*.bin",
     "llama_LAYER0_OUT_pos0_layer0_full_n2048_*.bin", "seq077"),
]

lines = []
lines.append("A1_HARD_L2_Q_PRE_ROPE_remeasure.compare")
lines.append("METHOD=Deep2TensorCompare AND (abs>1e-4 && rel>1e-3)")
lines.append("PAIR=stage_dump_q4kq8k_spv vs stage_dump_ref_matched")
lines.append(f"ASOF={datetime.now().isoformat(timespec='seconds')}")
print("=== AFTER Q4KxQ8K ===")
q_fail = None
q_max = None
for name, gpat, rpat, pref in pairs:
    gp = pick(gpu, gpat)
    rp = pick(ref, rpat, pref)
    if not gp or not rp:
        line = f"{name}: MISSING g={gp} r={rp}"
        print(line)
        lines.append(line)
        continue
    a = load(gp)
    b = load(rp)
    n, mx, mr, first, fails = cmp_t(a, b)
    fg = fnv(gp)
    fr = fnv(rp)
    line = (
        f"{name}: FNV_DIFF={int(fg != fr)} FUNCTIONAL_FAIL={int(fails > 0)} "
        f"MAX_ABS={mx:.6e} MAX_REL={mr:.6e} first_bad={first} fails={fails} "
        f"gpu={os.path.basename(gp)} ref={os.path.basename(rp)} "
        f"fnvA={fg} fnvB={fr}"
    )
    print(line)
    lines.append(line)
    if name == "Q_PRE_ROPE_0":
        q_fail = int(fails > 0)
        q_max = mx
        ae = abs(a[2] - b[2])
        den = max(abs(a[2]), abs(b[2]))
        re = ae / den if den > 1e-20 else ae
        extra = (
            f"  idx2: a={a[2]:.6e} b={b[2]:.6e} abs={ae:.6e} rel={re:.6e} "
            f"HARD_ELEM={int(ae > ABS and re > REL)}"
        )
        print(extra)
        lines.append(extra)

print("=== BEFORE F28F ===")
gp = pick(gpu_old, "deep2_Q_PRE_ROPE_0_pos0_layer0_full_n2048_*.bin")
rp = pick(ref, "llama_Q_PRE_ROPE_0_pos0_layer0_full_n2048_*.bin", "seq005")
a = load(gp)
b = load(rp)
n, mx, mr, first, fails = cmp_t(a, b)
before = (
    f"Q_PRE_ROPE_0_BEFORE: FUNCTIONAL_FAIL={int(fails > 0)} MAX_ABS={mx:.6e} "
    f"first_bad={first} idx2_abs={abs(a[2] - b[2]):.6e}"
)
print(before)
lines.append(before)

spv = r"G:\~dev\rawrxd\src\backend\gemv_q4k.spv"
h = hashlib.sha256(open(spv, "rb").read()).hexdigest().upper()
spvline = f"SPV_SHA256={h} LEN={os.path.getsize(spv)}"
print(spvline)
lines.append(spvline)
lines.append(f"Q_PRE_ROPE_0_HARD_L2_PASS={int(q_fail == 0)}")
lines.append(f"Q_PRE_ROPE_0_MAX_ABS_ERR={q_max:.6e}" if q_max is not None else "Q_PRE_ROPE_0_MAX_ABS_ERR=NA")

outp = os.path.join(ev, "A1_HARD_L2_Q_PRE_ROPE_remeasure.compare.txt")
with open(outp, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
print("WROTE", outp)
