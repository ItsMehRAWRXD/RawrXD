#!/usr/bin/env python3
"""DEEP2_QUANT_ADJUDICATOR_RECEIPT_001 — formalized machine-readable receipt.

Q's recommendation implemented: every kernel adjudicator invocation writes a
single machine-readable receipt (JSON) recording:

  GGUF SHA-256, trace SHA-256, engine commit, reference commit,
  tensor name, quant type, max abs error, max rel error,
  first mismatching index, correlation coefficient, PASS/FAIL.

Usage:
  python _quant_adjudicator.py <model.gguf> <trace.txt> <tensor_name>
      [--rows N] [--steps LAST] [--out receipt.json]

Covers Q4_K (blk-144-byte) and Q6_K (blk-210-byte) tensors. The reference is
llama.cpp-verbatim (fetched from ggml-quants.c, get_scale_min_k4 + dequantize
_row_q4_K / dequantize_row_q6_K). The engine side is read from the trace's
full-vector checkpoint records (VEC=LAYER_N_<NAME>), with the matching GEMV
input (ATTN_NORM for attn projections, FFN_NORM for gate/up, SWIGLU for down).

Exit code 0 = PASS, 1 = FAIL, 2 = usage/IO error. Receipt JSON is always
written (even on FAIL/HOLD) so regressions are diffable.
"""
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

import numpy as np

REPO = r"F:\\~dev\\rawrxd"



def _resolve_out(argv, trace):
    for i, a in enumerate(argv):
        if a == "--out" and i + 1 < len(argv):
            return argv[i + 1]
    return trace + ".adj.json"


def sha256_file(path, max_mb=4096):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(4 * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().upper()


def git_commit(repo, path=None):
    args = ["git", "-C", repo, "rev-parse", "--short=9", "HEAD"]
    if path:
        args = ["git", "-C", repo, "log", "-1", "--format=%h", "--", path]
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=30)
        s = out.stdout.strip()
        return s if s else "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def fp16_tab():
    def f16_scalar(h):
        s = -1.0 if h & 0x8000 else 1.0
        e = (h >> 10) & 0x1F
        fr = h & 0x3FF
        if e == 0:
            return s * fr * 2.0 ** -24
        return s * (1.0 + fr / 1024.0) * 2.0 ** (e - 15)

    return np.array([f16_scalar(i) for i in range(65536)], dtype=np.float32)


F16_TAB = fp16_tab()


def parse_header(path):
    f = open(path, "rb")
    f.read(4)
    struct.unpack("<I", f.read(4))
    n_tensors = struct.unpack("<Q", f.read(8))[0]
    n_kv = struct.unpack("<Q", f.read(8))[0]

    def read_str(fh):
        n = struct.unpack("<Q", fh.read(8))[0]
        return fh.read(n).decode("utf-8", "replace")

    def skip_value(fh, t):
        if t == 8:
            read_str(fh)
        elif t in (0, 1, 7):
            fh.seek(1, 1)
        elif t in (2, 3):
            fh.seek(2, 1)
        elif t in (4, 5, 6):
            fh.seek(4, 1)
        elif t in (10, 11, 12):
            fh.seek(8, 1)
        elif t == 9:
            et = struct.unpack("<I", fh.read(4))[0]
            n = struct.unpack("<Q", fh.read(8))[0]
            for _ in range(n):
                skip_value(fh, et)
        else:
            raise ValueError(t)

    for _ in range(n_kv):
        read_str(f)
        t = struct.unpack("<I", f.read(4))[0]
        skip_value(f, t)
    tinfos = {}
    for _ in range(n_tensors):
        name = read_str(f)
        nd = struct.unpack("<I", f.read(4))[0]
        dims = struct.unpack("<" + "Q" * nd, f.read(8 * nd))
        ttype = struct.unpack("<I", f.read(4))[0]
        off = struct.unpack("<Q", f.read(8))[0]
        tinfos[name] = (dims, ttype, off)
    # GGUF v3: tensor data offsets are relative to the aligned position after
    # all tensor headers (llama.cpp convention, same as qwen2_l4_reference).
    data_start = (f.tell() + 31) // 32 * 32
    f.close()
    return tinfos, data_start


def parse_trace_vecs(trace_path):
    """Returns {key: {step: vector}} from VEC=LAYER_N_KEY records."""
    vecs = {}
    cur = None
    step = -1
    buf = []
    head = re.compile(r"^STEP=(\d+) VEC=(\S+) N=(\d+)")
    data = re.compile(r"^-?[0-9.eE+,\-]+$")
    with open(trace_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            m = head.match(line)
            if m:
                if cur:
                    vecs.setdefault(cur[0], {})[cur[1]] = np.asarray(buf, dtype=np.float64)
                step, key = int(m.group(1)), m.group(2)
                cur = (key, step)
                buf = []
                continue
            if cur and data.fullmatch(line):
                buf.extend(float(x) for x in line.split(","))
    if cur:
        vecs.setdefault(cur[0], {})[cur[1]] = np.asarray(buf, dtype=np.float64)
    return vecs


# ---------------------------------------------------------------------------
# llama.cpp-verbatim reference decodes
# ---------------------------------------------------------------------------
def get_scale_min_k4(j, q):
    if j < 4:
        return q[j] & 63, q[j + 4] & 63
    d = (q[j + 4] & 0xF) | ((q[j - 4] >> 6) << 4)
    m = (q[j + 4] >> 4) | ((q[j] >> 6) << 4)
    return d, m


def deq_q4k_row(row_bytes, ne0, bpr):
    """llama dequantize_row_q4_K verbatim (144 bytes/block)."""
    vals = np.empty(ne0, dtype=np.float64)
    for b in range(bpr):
        blk = row_bytes[b * 144:(b + 1) * 144]
        d = float(F16_TAB[struct.unpack("<H", blk[0:2])[0]])
        dmin = float(F16_TAB[struct.unpack("<H", blk[2:4])[0]])
        s = blk[4:16].astype(np.int64)
        q = blk[16:144].astype(np.int64)
        for chunk in range(4):
            isb = chunk * 2
            sc0, mn0 = get_scale_min_k4(isb, s)
            sc1, mn1 = get_scale_min_k4(isb + 1, s)
            base = b * 256 + chunk * 64
            seg = q[chunk * 32:(chunk + 1) * 32]
            vals[base + 0:base + 32] = d * sc0 * (seg & 0xF) - dmin * mn0
            vals[base + 32:base + 64] = d * sc1 * (seg >> 4) - dmin * mn1
    return vals


def deq_q6k_row(row_bytes, ne0, bpr):
    """llama dequantize_row_q6_K verbatim (210 bytes/block) with the STRIDED
    canonical scale mapping (q6k_kernel_parity_test canon_dequant_block).
    Two 128-value chunks per block; each writes 32 groups of 4 quarters."""
    vals = np.empty(ne0, dtype=np.float64)
    for b in range(bpr):
        blk = row_bytes[b * 210:(b + 1) * 210]
        d = float(F16_TAB[struct.unpack("<H", blk[208:210])[0]])
        ql = blk[0:128].astype(np.int64)
        qh = blk[128:192].astype(np.int64)
        sc = np.frombuffer(blk[192:208], dtype=np.int8).astype(np.int64)
        qi = hi = sci = 0
        for n in range(0, 256, 128):
            base = b * 256 + n
            for l in range(32):
                is_ = l // 16
                q1 = ((ql[qi + l] & 0xF) | (((qh[hi + l] >> 0) & 3) << 4)) - 32
                q2 = ((ql[qi + l + 32] & 0xF) | (((qh[hi + l] >> 2) & 3) << 4)) - 32
                q3 = ((ql[qi + l] >> 4) | (((qh[hi + l] >> 4) & 3) << 4)) - 32
                q4 = ((ql[qi + l + 32] >> 4) | (((qh[hi + l] >> 6) & 3) << 4)) - 32
                vals[base + l + 0] = d * float(sc[sci + is_ + 0]) * float(q1)
                vals[base + l + 32] = d * float(sc[sci + is_ + 2]) * float(q2)
                vals[base + l + 64] = d * float(sc[sci + is_ + 4]) * float(q3)
                vals[base + l + 96] = d * float(sc[sci + is_ + 6]) * float(q4)
            qi += 64
            hi += 32
            sci += 8
    return vals
QK_TENSORS = {12: ("Q4_K", 144, deq_q4k_row), 14: ("Q6_K", 210, deq_q6k_row)}

# input-vector key per tensor family; position key = which output slot of the
# trace vector corresponds to weight row r.
INPUT_MAP = {
    "attn_q.weight": "ATTN_NORM",
    "attn_k.weight": "ATTN_NORM",
    "attn_v.weight": "ATTN_NORM",
    "attn_output.weight": "ATTN_VALUE",
    "ffn_gate.weight": "FFN_NORM",
    "ffn_up.weight": "FFN_NORM",
    "ffn_down.weight": "SWIGLU",
}
OUTPUT_MAP = {
    "attn_q.weight": "Q",
    "attn_k.weight": "K",
    "attn_v.weight": "V",
    "attn_output.weight": "O_PROJ",
    "ffn_gate.weight": "FFN_GATE",
    "ffn_up.weight": "FFN_UP",
    "ffn_down.weight": "FFN_DOWN",
}
BIAS_MAP = {
    "attn_q.weight": "blk.{L}.attn_q.bias",
    "attn_k.weight": "blk.{L}.attn_k.bias",
    "attn_v.weight": "blk.{L}.attn_v.bias",
}


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    model = sys.argv[1]
    trace = sys.argv[2]
    tensor = sys.argv[3]
    rows_n = int(sys.argv[4]) if len(sys.argv) > 4 else 4
    step = int(sys.argv[5]) if len(sys.argv) > 5 else 0

    rec = {
        "receipt": "DEEP2_QUANT_ADJUDICATOR_RECEIPT_001",
        "gguf": model,
        "gguf_sha256": None,
        "trace": trace,
        "trace_sha256": None,
        "engine_commit": git_commit(REPO),
        "reference": "llama.cpp ggml-quants.c dequantize_row_q4_K/q6_K (verbatim)",
        "reference_commit": None,
        "tensor": tensor,
        "quant_type": None,
        "step": step,
        "rows_tested": 0,
        "max_abs_error": None,
        "max_rel_error": None,
        "first_mismatch_index": None,
        "correlation": None,
        "verdict": "HOLD",
        "fail_reason": None,
    }

    try:
        rec["gguf_sha256"] = sha256_file(model)
        rec["trace_sha256"] = sha256_file(trace)
    except OSError as e:
        rec["fail_reason"] = f"io:{e}"
        Path(_resolve_out(sys.argv, trace)).write_text(
            json.dumps(rec, indent=2))
        print(json.dumps(rec, indent=2))
        return 2

    tinfos, data_start = parse_header(model)
    if tensor not in tinfos:
        rec["fail_reason"] = "tensor_not_found"
        Path(_resolve_out(sys.argv, trace)).write_text(
            json.dumps(rec, indent=2))
        print(json.dumps(rec, indent=2))
        return 2

    dims, ttype, off = tinfos[tensor]
    if ttype not in QK_TENSORS:
        rec["quant_type"] = str(ttype)
        rec["fail_reason"] = "unsupported_quant_type"
        Path(_resolve_out(sys.argv, trace)).write_text(
            json.dumps(rec, indent=2))
        print(json.dumps(rec, indent=2))
        return 2

    qname, block_bytes, dequant = QK_TENSORS[ttype]
    rec["quant_type"] = qname

    # ne[0] = contiguous per-row length (contraction), ne[1] = row count.
    ne0, ne1 = dims[0], dims[1]
    bpr = ne0 // 256
    rb = bpr * block_bytes

    vecs = parse_trace_vecs(trace)

    # locate the layer number from the tensor name
    lm = re.match(r"blk\.(\d+)\.", tensor)
    layer = lm.group(1) if lm else None
    suffix = tensor.split(".", 2)[2] if layer is not None else None
    in_key = INPUT_MAP.get(suffix) if suffix else None
    out_key = OUTPUT_MAP.get(suffix) if suffix else None
    layer_key = f"LAYER_{layer}" if layer is not None else None
    if layer and (f"LAYER_{layer}_{in_key}" in vecs):
        in_key = f"LAYER_{layer}_{in_key}"
        out_key = f"LAYER_{layer}_{out_key}"

    if in_key not in vecs or out_key not in vecs or step not in vecs[in_key]:
        rec["fail_reason"] = f"trace_missing:{in_key}@{step} or {out_key}"
        Path(_resolve_out(sys.argv, trace)).write_text(
            json.dumps(rec, indent=2))
        print(json.dumps(rec, indent=2))
        return 2

    x = vecs[in_key][step].ravel()
    got = vecs[out_key][step].ravel()

    with open(model, "rb") as f:
        f.seek(data_start + off)
        nbytes = ne1 * rb
        raw = np.frombuffer(f.read(nbytes), dtype=np.uint8).reshape(ne1, rb)

    # bias (attention projections in Qwen2 have one; ffn does not)
    bias = None
    if suffix and suffix in BIAS_MAP:
        bname = BIAS_MAP[suffix].format(L=layer)
        if bname in tinfos:
            bdims, _, boff = tinfos[bname]
            with open(model, "rb") as f:
                f.seek(data_start + boff)
                bias = np.frombuffer(f.read(bdims[0] * 4), dtype="<f4").astype(np.float64)

    max_abs = 0.0
    max_rel = 0.0
    first_bad = None
    g_list = []
    r_list = []
    scale = 0.0
    for r in range(min(rows_n, ne1)):
        W = dequant(raw[r], ne0, bpr)
        ref = float(np.dot(W, x))
        if bias is not None:
            ref += float(bias[r])
        g = float(got[r])
        g_list.append(g)
        r_list.append(ref)
        scale = max(scale, abs(ref))
        a = abs(g - ref)
        rel = a / max(abs(ref), 1e-9)
        if a > max_abs:
            max_abs = a
        if rel > max_rel:
            max_rel = rel
        if a > max(0.01 * abs(ref), 0.05) and first_bad is None:
            first_bad = r

    rec["rows_tested"] = len(g_list)
    rec["max_abs_error"] = max_abs
    rec["max_rel_error"] = max_rel
    rec["first_mismatch_index"] = first_bad
    if len(g_list) >= 2 and max(scale, 1e-9) > 1e-6:
        ga = np.asarray(g_list)
        ra = np.asarray(r_list)
        if ga.std() > 1e-12 and ra.std() > 1e-12:
            rec["correlation"] = float(np.corrcoef(ga, ra)[0, 1])
        else:
            rec["correlation"] = 0.0
    else:
        rec["correlation"] = None

    passed = first_bad is None
    rec["verdict"] = "PASS" if passed else "FAIL"

    outp = _resolve_out(sys.argv, trace)
    Path(outp).write_text(json.dumps(rec, indent=2))
    print(json.dumps(rec, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())




