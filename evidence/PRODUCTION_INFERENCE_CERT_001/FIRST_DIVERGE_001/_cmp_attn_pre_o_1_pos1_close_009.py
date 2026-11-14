"""CLOSE_009 compare: hybridB remasure + head16 knife isolate. PROMOTE=0 INVENT_PASS=0."""
import os, hashlib
from datetime import datetime
import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gpu = os.path.join(ev, "stage_dump_attn_pre_o_1_pos1_close009_hybridb")
ref = os.path.join(ev, "stage_dump_ref_matched")
ABS, REL = 1e-6, 1e-5
BEFORE = 9.397045e-06


def load(p):
    return np.fromfile(p, dtype=np.float32)


def pick(d, key, side="deep2", extra="_n2048_"):
    needle = f"{side}_{key}_"
    hits = sorted(
        os.path.join(d, n)
        for n in os.listdir(d)
        if n.endswith(".bin") and needle in n and extra in n
    )
    return hits[0] if hits else None


def pick_any(d, key, side="deep2"):
    needle = f"{side}_{key}_"
    hits = sorted(
        os.path.join(d, n)
        for n in os.listdir(d)
        if n.endswith(".bin") and needle in n
    )
    return hits[0] if hits else None


def cmp(a, b):
    n = min(len(a), len(b))
    mx = mr = 0.0
    idx = -1
    ng = 0
    for i in range(n):
        ae = abs(float(a[i] - b[i]))
        den = max(abs(float(a[i])), abs(float(b[i])), 1e-20)
        re = ae / den
        if ae > mx:
            mx, idx, mr = ae, i, re
        if ae > ABS:
            ng += 1
    return n, mx, mr, idx, ng


def f16(x):
    return float(np.float32(x).astype(np.float16).astype(np.float32))


def ulp(a, b):
    return abs(int(np.float32(a).view(np.uint32)) - int(np.float32(b).view(np.uint32)))


def main():
    lines = []
    asof = datetime.now().astimezone().isoformat(timespec="seconds")
    exe = os.path.join(ev, "pin", "rawr_attn_pre_o_1_pos1_fa006.exe")
    spv = os.path.join(ev, "pin", "gemv_q4k.spv")
    art = r"G:\~dev\rawrxd\src\backend\gemv_q4k.spv.hybridB_close008"
    lines.append("GPU_PARITY_ATTN_PRE_O_1_POS1_CLOSE_009.compare.log")
    lines.append(f"ASOF={asof}")
    lines.append(f"GPU_DIR={gpu}")
    lines.append(f"REF_DIR={ref}")
    lines.append("CAND=pin/rawr_attn_pre_o_1_pos1_fa006.exe")
    lines.append(
        f"EXE_SHA256={hashlib.sha256(open(exe, 'rb').read()).hexdigest().upper()}"
    )
    for label, path in [("PIN_SPV", spv), ("ART_SPV", art)]:
        if os.path.isfile(path):
            lines.append(
                f"{label}_SHA256={hashlib.sha256(open(path, 'rb').read()).hexdigest().upper()} "
                f"LEN={os.path.getsize(path)}"
            )
    lines.append(
        "ENV=FORCE_VULKAN_QUANT_GEMV=1 Q4_HOST_ATTN=0 Q4_HOST_FFN_DOWN=0 "
        "KV_FP16_ROUNDTRIP=1 GPU_FWD=0 FA_F16=1"
    )
    lines.append(f"BEFORE_CLOSE008={BEFORE:.6e}")

    keys = [
        ("ATTN_PRE_O_0_pos0", "_n2048_"),
        ("ATTN_PRE_O_0_pos1", "_n2048_"),
        ("FFN_DOWN_0_pos0", "_n2048_"),
        ("FFN_DOWN_2_pos1", "_n2048_"),
        ("V_1_pos0", "_n256_"),
        ("Q_PRE_ROPE_1_pos1", "_n2048_"),
        ("ATTN_PRE_O_1_pos0", "_n2048_"),
        ("ATTN_PRE_O_1_pos1", "_n2048_"),
    ]
    holds = {}
    for k, ex in keys:
        gp = pick(gpu, k, "deep2", ex) if ex == "_n2048_" else pick_any(gpu, k, "deep2")
        rp = pick(ref, k, "llama", ex) if ex == "_n2048_" else pick_any(ref, k, "llama")
        if k.startswith("FFN_") and not rp:
            rp = pick(os.path.join(ev, "stage_dump_gpu_ref"), k, "llama", ex)
        if not gp or not rp:
            lines.append(f"{k}: MISSING gpu={bool(gp)} ref={bool(rp)}")
            continue
        n, mx, mr, idx, ng = cmp(load(gp), load(rp))
        under = int(mx <= ABS)
        lines.append(
            f"{k}: maxAbs={mx:.6e} rel={mr:.6e} @idx{idx} n_gt={ng}/{n} UNDER_TOL={under}"
        )
        holds[k] = (mx, under, idx)

    gpo_hits = sorted(
        os.path.join(gpu, n)
        for n in os.listdir(gpu)
        if n.startswith("deep2_Q_POST_ROPE_1_pos1_") and "_n2048_" in n
    )
    rpo = os.path.join(ref, "llama_Q_POST_ROPE_1_pos1_layer0_full_n2048_seq102.bin")
    if gpo_hits and os.path.isfile(rpo):
        a, b = load(gpo_hits[0]), load(rpo)
        lines.append(
            f"Q_POST_ROPE_1_pos1: maxAbs={cmp(a, b)[1]:.6e} (gpu={os.path.basename(gpo_hits[0])})"
        )
        for idx in (747, 1026):
            lines.append(
                f"KNIFE_Q_POST_idx{idx} gpu={float(a[idx]):.10e} ref={float(b[idx]):.10e} "
                f"F16_gpu={f16(a[idx])} F16_ref={f16(b[idx])} "
                f"F16_ne={int(f16(a[idx]) != f16(b[idx]))} ulp={ulp(a[idx], b[idx])}"
            )
        gpre = pick(gpu, "Q_PRE_ROPE_1_pos1")
        rpre = pick(ref, "Q_PRE_ROPE_1_pos1")
        if gpre and rpre:
            gp_, rp_ = load(gpre), load(rpre)
            lines.append(
                f"KNIFE_Q_PRE_idx1027 gpu={float(gp_[1027]):.10e} ref={float(rp_[1027]):.10e} "
                f"ulp={ulp(gp_[1027], rp_[1027])}"
            )

    pre_o = holds.get("ATTN_PRE_O_1_pos1", (None, 0, -1))
    after = pre_o[0]
    closed = int(after is not None and after <= ABS)
    lines.append(f"AFTER_maxAbs={after}")
    lines.append(f"ATTN_PRE_O_1_POS1_CLOSE={closed}")
    lines.append(
        "REGRESSION_HOLD="
        f"{int(holds.get('FFN_DOWN_0_pos0', (9, 0))[1] and holds.get('FFN_DOWN_2_pos1', (9, 0))[1] and holds.get('ATTN_PRE_O_0_pos1', (9, 0))[1])}"
    )
    lines.append(f"RESULT={'CLOSED' if closed else 'OPEN'}")
    lines.append("PROMOTE=0 TIP_CLIMB=HOLD")

    out = os.path.join(ev, "GPU_PARITY_ATTN_PRE_O_1_POS1_CLOSE_009.compare.log")
    open(out, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    print("\n".join(lines))
    print("WROTE", out)


if __name__ == "__main__":
    main()
