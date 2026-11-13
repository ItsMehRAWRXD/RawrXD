import struct, math, pathlib
ev = pathlib.Path(r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001")

def fnv1a64(data: bytes) -> str:
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return f"{h:016x}"

def load(p, n=None):
    raw = pathlib.Path(p).read_bytes()
    if n is None:
        n = len(raw) // 4
    raw = raw[: n * 4]
    return struct.unpack("<%df" % n, raw), raw

def l2(xs):
    return math.sqrt(sum(x * x for x in xs))

def rel_l2(a, b):
    num = sum((x - y) * (x - y) for x, y in zip(a, b))
    den = sum(y * y for y in b)
    return math.sqrt(num) / (math.sqrt(den) + 1e-30), max(abs(x - y) for x, y in zip(a, b))

gpu_v = ev / "stage_dump_v0_remeasure_gpu" / "deep2_V_0_pos0_layer0_full_n256_seq003.bin"
host_v = ev / "stage_dump_v0_remeasure_host" / "deep2_V_0_pos0_layer0_full_n256_seq003.bin"
ref_v = ev / "stage_dump_gpu_fix" / "llama_V_0_pos0_layer0_full_n256_seq011.bin"
gpu_q = ev / "stage_dump_v0_remeasure_gpu" / "deep2_Q_PRE_ROPE_0_pos0_layer0_full_n2048_seq008.bin"
host_q = ev / "stage_dump_v0_remeasure_host" / "deep2_Q_PRE_ROPE_0_pos0_layer0_full_n2048_seq008.bin"
ref_q = ev / "stage_dump_gpu_fix" / "llama_Q_PRE_ROPE_0_pos0_layer0_full_n2048_seq005.bin"
lines = []
for name, p, n in [
    ("GPU_V0", gpu_v, 256), ("HOST_V0", host_v, 256), ("REF_V0", ref_v, 256),
    ("GPU_Q", gpu_q, 2048), ("HOST_Q", host_q, 2048), ("REF_Q", ref_q, 2048),
]:
    xs, raw = load(p, n)
    lines.append(f"{name} path={p} l2={l2(xs):.9e} fnv={fnv1a64(raw)}")
g, _ = load(gpu_v, 256); h, _ = load(host_v, 256); r, _ = load(ref_v, 256)
rel, mx = rel_l2(g, r)
lines += [
    f"GPU_HOST_V0_MATCH={int(g == h)}",
    f"GPU_REF_V0_rel={rel:.9e} maxAbs={mx:.9e}",
    f"GPU_REF_V0_L2_NEAR={int(rel < 1e-6)}",
    f"GPU_REF_V0_FNV_BITEXACT={int(g == r)}",
]
gq, _ = load(gpu_q, 2048); hq, _ = load(host_q, 2048); rq, _ = load(ref_q, 2048)
relq, mxq = rel_l2(gq, rq)
lines += [
    f"GPU_HOST_Q_MATCH={int(gq == hq)}",
    f"GPU_REF_Q_rel={relq:.9e} maxAbs={mxq:.9e}",
    f"GPU_REF_Q_FNV_BITEXACT={int(gq == rq)}",
]
(ev / "V0_REMEASURE_001.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("\n".join(lines))
