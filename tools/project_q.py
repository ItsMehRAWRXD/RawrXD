#!/usr/bin/env python3
"""Independent Q-projection - RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001

Recomputes the layer-0 Q projection in Python from the independently
dequantized (and verified bit-identical) attn_q weight, then compares the
result against both the native op3 capture and the llama.cpp reference.
"""
import math
import struct

NAT = "tmp_build_mg/native_p0/rec_000010_op3_Linear_Output_l0_p0_output.bin"
REFQ = "evidence/NUGVERSE_ESTIMATOR_001/ref_capture_v9/ref_l00_p00_q.bin"
REFN = "evidence/NUGVERSE_ESTIMATOR_001/ref_capture_v9/ref_l00_p00_attn_norm.bin"
W = "tmp_build_mg/attn_q_ref.f32"
IN = 2048
OUT = 3072


def rd_nat(p):
    d = open(p, "rb").read()
    (nd,) = struct.unpack_from("<I", d, 16)
    off = 20 + 8 * nd
    (cnt,) = struct.unpack_from("<Q", d, off)
    off += 8
    return struct.unpack("<%df" % cnt, d[off:off + cnt * 4])


def rd_ref(p):
    d = open(p, "rb").read()
    (nlen,) = struct.unpack_from("<I", d, 16)
    off = 20 + nlen
    (nd,) = struct.unpack_from("<I", d, off)
    off += 4
    off += 8 * nd
    return struct.unpack("<%df" % ((len(d) - off) // 4), d[off:])


def met(a, b):
    n = min(len(a), len(b))
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    rm = math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)) / n)
    mx = max(abs(x - y) for x, y in zip(a, b))
    return "n=%d cos=%.9f rmse=%.6g max|d|=%.6g" % (n, dot / (na * nb), rm, mx)


norm = rd_ref(REFN)
raw = open(W, "rb").read()
w = struct.unpack("<%df" % (len(raw) // 4), raw)
assert len(w) == IN * OUT, (len(w), IN * OUT)

q = [0.0] * OUT
for i in range(OUT):
    base = i * IN
    s = 0.0
    for j in range(IN):
        s += norm[j] * w[base + j]
    q[i] = s

nat = rd_nat(NAT)
rr = rd_ref(REFQ)

print("layout w[j + i*IN]  vs native op3 :", met(q, nat))
print("layout w[j + i*IN]  vs ref q      :", met(q, rr))
print("independent [:6]", [round(x, 6) for x in q[:6]])
print("native       [:6]", [round(x, 6) for x in nat[:6]])
print("reference    [:6]", [round(x, 6) for x in rr[:6]])

# Also test the transposed layout w[i + j*OUT].
q2 = [0.0] * OUT
for i in range(OUT):
    s = 0.0
    for j in range(IN):
        s += norm[j] * w[i + j * OUT]
    q2[i] = s
print("layout w[i + j*OUT] vs native op3 :", met(q2, nat))
print("layout w[i + j*OUT] vs ref q      :", met(q2, rr))
