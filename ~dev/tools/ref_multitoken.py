# DEEP2_QWEN25_MULTITOKEN_KV_PARITY_001 — Python reference (multi-position)
#
# Independent Qwen2.5 forward with a REAL KV cache across positions 0..N-1
# greedy-decoded from a single-token prompt. Emits the same trace format as
# the Deep2 C++ probe.
#
# Memory-optimised: dequantizes one layer at a time on demand.  Checkpoint
# after every step so a killed process can be resumed.
#
# Usage: python ref_multitoken.py <model.gguf> <tokenId> <nPositions>
# Output: prints trace to stdout (redirect to mt_ref.txt)
import struct
import sys
import os
import numpy as np

MODEL = sys.argv[1] if len(sys.argv) > 1 else \
    r"F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf"
TOKEN_ID = int(sys.argv[2]) if len(sys.argv) > 2 else 750
NPOS = int(sys.argv[3]) if len(sys.argv) > 3 else 8
CHECKPOINT_PATH = r"F:\~dev\mt_ref_checkpoint.npz"

TYPE_Q4_K, TYPE_Q6_K, TYPE_F32 = 12, 14, 0
BLOCK_VALS = 256

# ---------------------------------------------------------------------------
def _read_val(fh, vtype):
    if vtype == 8:
        n = struct.unpack("<Q", fh.read(8))[0]
        return fh.read(n).decode("utf-8", "replace"), fh
    if vtype == 9:
        etype = struct.unpack("<I", fh.read(4))[0]
        count = struct.unpack("<Q", fh.read(8))[0]
        if etype == 8:
            vals = []
            for _ in range(count):
                n = struct.unpack("<Q", fh.read(8))[0]
                vals.append(fh.read(n).decode("utf-8", "replace"))
            return vals, fh
        fmtc = {0:("B",1),1:("b",1),2:("H",2),3:("h",2),4:("I",4),5:("i",4),
                6:("f",4),7:("?",1),10:("Q",8),11:("q",8),12:("d",8)}
        c, esz = fmtc[etype]
        return list(struct.unpack(f"<{count}{c}", fh.read(esz * count))), fh
    fmtc = {0:("B",1),1:("b",1),2:("H",2),3:("h",2),4:("I",4),5:("i",4),
            6:("f",4),7:("?",1),10:("Q",8),11:("q",8),12:("d",8)}
    c, esz = fmtc[vtype]
    return struct.unpack(f"<{c}", fh.read(esz))[0], fh

def read_header_kv(path):
    meta = {}
    with open(path, "rb") as fh:
        magic, version, tcount, kvcount = struct.unpack("<4sIQQ", fh.read(24))
        assert magic == b"GGUF"
        for _ in range(kvcount):
            klen = struct.unpack("<Q", fh.read(8))[0]
            key = fh.read(klen).decode("utf-8", "replace")
            vtype = struct.unpack("<I", fh.read(4))[0]
            val, fh = _read_val(fh, vtype)
            meta[key] = val
        hdr_end = fh.tell()
    return meta, tcount, hdr_end

KMASK1, KMASK2, KMASK3 = 0x3F3F3F3F, 0x0F0F0F0F, 0x03030303

def dequant_q4_k_vec(src):
    nb = src.shape[0]
    d = src[:, 0:2].copy().view(np.float16).astype(np.float32)
    dmin = src[:, 2:4].copy().view(np.float16).astype(np.float32)
    utmp = np.zeros((nb, 4), dtype=np.uint32)
    utmp[:, 0:3] = src[:, 4:16].copy().view(np.uint32)
    utmp[:, 3] = ((utmp[:, 2] >> 4) & KMASK2) | (((utmp[:, 1] >> 6) & KMASK3) << 4)
    uaux = utmp[:, 1] & KMASK1
    utmp[:, 1] = (utmp[:, 2] & KMASK2) | (((utmp[:, 0] >> 6) & KMASK3) << 4)
    utmp[:, 2] = uaux
    utmp[:, 0] &= KMASK1
    packed = utmp.view(np.uint8)
    sc = packed[:, 0:8].astype(np.float32)
    mn = packed[:, 8:16].astype(np.float32)
    qs = src[:, 16:144]
    out = np.empty((nb, BLOCK_VALS), dtype=np.float32)
    for g in range(4):
        j = g * 64
        is_ = g * 2
        q = qs[:, g * 32:(g + 1) * 32]
        lo = (q & 0x0F).astype(np.float32)
        hi = (q >> 4).astype(np.float32)
        out[:, j:j + 32] = d * sc[:, is_:is_ + 1] * lo - dmin * mn[:, is_:is_ + 1]
        out[:, j + 32:j + 64] = d * sc[:, is_ + 1:is_ + 2] * hi \
            - dmin * mn[:, is_ + 1:is_ + 2]
    return out.reshape(-1)

def dequant_q6_k_vec(src):
    nb = src.shape[0]
    ql = src[:, 0:128]
    qh = src[:, 128:192]
    scales = src[:, 192:208].copy().view(np.int8).astype(np.float32)
    d = src[:, 208:210].copy().view(np.float16).astype(np.float32)
    w = np.empty((nb, BLOCK_VALS), dtype=np.int32)
    for jj in range(2):
        q4 = ql[:, jj * 64:(jj + 1) * 64]
        q2 = qh[:, jj * 32:(jj + 1) * 32]
        base = jj * 128
        w[:, base + 0:base + 32] = ((q4[:, 0:32] & 0xF)
            | (((q2 >> 0) & 3) << 4)).astype(np.int32) - 32
        w[:, base + 32:base + 64] = ((q4[:, 32:64] & 0xF)
            | (((q2 >> 2) & 3) << 4)).astype(np.int32) - 32
        w[:, base + 64:base + 96] = ((q4[:, 0:32] >> 4)
            | (((q2 >> 4) & 3) << 4)).astype(np.int32) - 32
        w[:, base + 96:base + 128] = ((q4[:, 32:64] >> 4)
            | (((q2 >> 6) & 3) << 4)).astype(np.int32) - 32
    dexp = np.repeat(d * scales, 16, axis=1)
    return (dexp * w).reshape(-1)

def fnv1a_hash_f32(v):
    h = 1469598103934665603
    b = np.ascontiguousarray(v, dtype=np.float32).tobytes()
    for byte in b:
        h ^= byte
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h

def emit(step, cp, v, layer=None):
    v = np.asarray(v, dtype=np.float32)
    n = v.size
    fv = v[np.isfinite(v)].astype(np.float64)
    if fv.size:
        mn, mx = float(fv.min()), float(fv.max())
        mean = float(fv.sum() / fv.size)
        l2 = float(np.sqrt(np.sum(fv * fv)))
    else:
        mn = mx = mean = l2 = 0.0
    f8 = np.asarray(v[:8], dtype=np.float64).ravel()
    f8s = ",".join(f"{x:.9g}" for x in f8)
    lay = f" LAYER={layer}" if layer is not None else ""
    print(f"STEP={step} CP={cp}{lay} COUNT={n} MIN={mn:.9g} MAX={mx:.9g} "
          f"MEAN={mean:.9g} L2={l2:.9g} FIRST8={f8s} "
          f"HASH={fnv1a_hash_f32(v):016x}", flush=True)

def emit_kv(step, layer, k, v, n):
    k = np.asarray(k, dtype=np.float32); v = np.asarray(v, dtype=np.float32)
    kf = k[np.isfinite(k)].astype(np.float64)
    vf = v[np.isfinite(v)].astype(np.float64)
    print(f"STEP={step} CP=KV_WRITE LAYER={layer} COUNT={n} "
          f"K_MIN={kf.min():.9g} K_MAX={kf.max():.9g} "
          f"K_MEAN={kf.sum()/kf.size:.9g} K_L2={np.sqrt((kf*kf).sum()):.9g} "
          f"K_HASH={fnv1a_hash_f32(k):016x} "
          f"V_MIN={vf.min():.9g} V_MAX={vf.max():.9g} "
          f"V_MEAN={vf.sum()/vf.size:.9g} V_L2={np.sqrt((vf*vf).sum()):.9g} "
          f"V_HASH={fnv1a_hash_f32(v):016x}", flush=True)

def emit_top10(step, logits):
    logits = np.asarray(logits, dtype=np.float32)
    n = logits.size
    top_val = [-np.inf] * 10
    top_idx = [0] * 10
    for i in range(n):
        val = logits[i]
        for s in range(10):
            if val > top_val[s]:
                for t in range(9, s, -1):
                    top_val[t] = top_val[t - 1]
                    top_idx[t] = top_idx[t - 1]
                top_val[s] = val
                top_idx[s] = i
                break
    pairs = ",".join(f"{top_idx[s]}:{top_val[s]:.6f}" for s in range(10))
    print(f"STEP={step} CP=LOGITS_TOP10 TOP10={pairs}", flush=True)

# ---------------------------------------------------------------------------
print("parsing header...", flush=True)
meta, tcount, hdr_end = read_header_kv(MODEL)
arch = meta.get("general.architecture", "qwen2")
alignment = int(meta.get("general.alignment", 32))

H = int(meta[f"{arch}.embedding_length"])
L = int(meta[f"{arch}.block_count"])
NH = int(meta[f"{arch}.attention.head_count"])
NKH = int(meta[f"{arch}.attention.head_count_kv"])
EPS = float(meta[f"{arch}.attention.layer_norm_rms_epsilon"])
THETA = float(meta.get(f"{arch}.rope.freq_base", 10000.0))
print(f"ARCH={arch} H={H} L={L} HEADS={NH} KV_HEADS={NKH} HEAD_DIM={H//NH} "
      f"GQA_GROUP={NH//NKH} ROPE_THETA={THETA:g} ROPE_NEOX=1 RMS_EPS={EPS:g}",
      flush=True)

f = open(MODEL, "rb")
f.seek(hdr_end)
tinfo = {}
for _ in range(tcount):
    nlen = struct.unpack("<Q", f.read(8))[0]
    name = f.read(nlen).decode("utf-8", "replace")
    ndims = struct.unpack("<I", f.read(4))[0]
    dims = [struct.unpack("<Q", f.read(8))[0] for _ in range(ndims)]
    ttype = struct.unpack("<I", f.read(4))[0]
    toff = struct.unpack("<Q", f.read(8))[0]
    tinfo[name] = (dims, ttype, toff)

dir_end = f.tell()
data_start = (dir_end + alignment - 1) // alignment * alignment

BLOCK_BYTES = {TYPE_Q4_K: 144, TYPE_Q6_K: 210, TYPE_F32: 4}

def read_raw(name):
    dims, ttype, toff = tinfo[name]
    nvals = int(np.prod(dims))
    if ttype in (TYPE_Q4_K, TYPE_Q6_K):
        nb = (nvals + BLOCK_VALS - 1) // BLOCK_VALS
        nbytes = nb * BLOCK_BYTES[ttype]
    elif ttype == TYPE_F32:
        nbytes = nvals * 4
    else:
        raise RuntimeError(f"{name}: unsupported type {ttype}")
    f.seek(data_start + toff)
    return f.read(nbytes), dims, ttype

def deq_mat(name):
    raw, dims, ttype = read_raw(name)
    if ttype == TYPE_Q4_K:
        v = dequant_q4_k_vec(np.frombuffer(raw, dtype=np.uint8)
                             .reshape(-1, BLOCK_BYTES[TYPE_Q4_K]))
    elif ttype == TYPE_Q6_K:
        v = dequant_q6_k_vec(np.frombuffer(raw, dtype=np.uint8)
                             .reshape(-1, BLOCK_BYTES[TYPE_Q6_K]))
    else:
        v = np.frombuffer(raw, dtype=np.uint8).view(np.float32)
    cols = dims[0]
    rows = int(np.prod(dims[1:])) if len(dims) > 1 else 1
    if rows == 1 and cols == len(v):
        return v.astype(np.float32)
    return v.reshape(rows, cols).astype(np.float32)

def gemv(w, x, chunk=8192):
    rows, cols = w.shape
    out = np.empty(rows, dtype=np.float32)
    for r0 in range(0, rows, chunk):
        r1 = min(r0 + chunk, rows)
        out[r0:r1] = w[r0:r1] @ x
    return out

def rmsnorm(x, w):
    ss = float(np.dot(x, x))
    inv = 1.0 / np.sqrt(ss / x.size + EPS)
    return (x * inv * w).astype(np.float32)

def silu(x):
    return (x / (1.0 + np.exp(-x.astype(np.float64)))).astype(np.float32)

head_dim = H // NH
kv_dim = NKH * head_dim
half = head_dim // 2
group = NH // NKH

# --- load final norm once ---
fn_w = deq_mat("output_norm.weight")

# RoPE cos/sin per position (NeoX, rotated-half)
inv_f = THETA ** (-np.arange(half, dtype=np.float64) / half)

# --- embedding row dequant per token ---
def embed_row(tok):
    dims, ttype, toff = tinfo["token_embd.weight"]
    nb_per_row = (dims[0] + BLOCK_VALS - 1) // BLOCK_VALS
    row_bytes = nb_per_row * BLOCK_BYTES[TYPE_Q4_K]
    f.seek(data_start + toff + tok * row_bytes)
    raw = f.read(row_bytes)
    return dequant_q4_k_vec(
        np.frombuffer(raw, dtype=np.uint8).reshape(nb_per_row, 144))[:H]

# --- LM head chunked Q6_K ---
lm_dims, lm_ttype, lm_toff = tinfo["output.weight"]
lm_cols = lm_dims[0]
lm_rows = int(np.prod(lm_dims[1:]))
lm_nb_per_row = (lm_cols + BLOCK_VALS - 1) // BLOCK_VALS
lm_row_bytes = lm_nb_per_row * BLOCK_BYTES[TYPE_Q6_K]

def logits_top10_from(hn):
    logits = np.empty(lm_rows, dtype=np.float32)
    hn64 = hn.astype(np.float64)
    CH = 4096
    for r0 in range(0, lm_rows, CH):
        r1 = min(r0 + CH, lm_rows)
        f.seek(data_start + lm_toff + r0 * lm_row_bytes)
        raw = f.read((r1 - r0) * lm_row_bytes)
        blk = np.frombuffer(raw, dtype=np.uint8).reshape(
            (r1 - r0) * lm_nb_per_row, 210)
        deq = dequant_q6_k_vec(blk).reshape(r1 - r0, lm_cols)
        logits[r0:r1] = (deq.astype(np.float64) @ hn64).astype(np.float32)
        del blk, deq
    return logits

# --- KV cache: [L][NKH][NPOS][head_dim] ---
kcache = np.zeros((L, NKH, NPOS, head_dim), dtype=np.float32)
vcache = np.zeros((L, NKH, NPOS, head_dim), dtype=np.float32)

# --- checkpoint helpers ---
def save_checkpoint(pos, tok):
    np.savez(CHECKPOINT_PATH,
             kcache=kcache, vcache=vcache,
             pos=np.array(pos), tok=np.array(tok))

def load_checkpoint():
    if not os.path.exists(CHECKPOINT_PATH):
        return None
    ck = np.load(CHECKPOINT_PATH)
    kcache[:] = ck["kcache"]
    vcache[:] = ck["vcache"]
    return int(ck["pos"]), int(ck["tok"])

# --- on-demand layer weight dequantization (deleted immediately after use) ---
def deq_layer_weights(layer):
    p = f"blk.{layer}."
    wl = {
        "q": deq_mat(p + "attn_q.weight"),
        "k": deq_mat(p + "attn_k.weight"),
        "v": deq_mat(p + "attn_v.weight"),
        "o": deq_mat(p + "attn_output.weight"),
        "g": deq_mat(p + "ffn_gate.weight"),
        "u": deq_mat(p + "ffn_up.weight"),
        "d": deq_mat(p + "ffn_down.weight"),
        "an": deq_mat(p + "attn_norm.weight"),
        "fn": deq_mat(p + "ffn_norm.weight"),
    }
    for bn in ("attn_q", "attn_k", "attn_v"):
        raw = np.frombuffer(read_raw(p + bn + ".bias")[0], dtype=np.float32)
        wl["b" + bn[-1]] = raw
    return wl

def forward(tok_id, pos, verbose_cp):
    h = embed_row(tok_id)
    if verbose_cp:
        emit(pos, "EMBED", h)
    for layer in range(L):
        wl = deq_layer_weights(layer)
        x = h

        # --- attention branch ---
        xn = rmsnorm(x, wl["an"])
        if verbose_cp:
            emit(pos, "ATTN_NORM", xn, layer=layer)

        q = gemv(wl["q"], xn) + wl["bq"]
        k = gemv(wl["k"], xn) + wl["bk"]
        v = gemv(wl["v"], xn) + wl["bv"]
        if verbose_cp:
            emit(pos, "Q", q, layer=layer)
            emit(pos, "K", k, layer=layer)
            emit(pos, "V", v, layer=layer)

        q = q.reshape(NH, head_dim)
        k = k.reshape(NKH, head_dim)
        v = v.reshape(NKH, head_dim)

        ang = pos * inv_f
        cs, sn = np.cos(ang), np.sin(ang)
        # NOTE: copy() the halves before writing back — q[:, :half] etc. are
        # views, and writing the first half would alias the second line's
        # qh_ read (the pre-fix reference produced a non-orthonormal "rotation",
        # broke norm preservation, and flipped the step-6 argmax).
        qh_, qh2 = q[:, :half].copy(), q[:, half:].copy()
        q[:, :half] = qh_ * cs - qh2 * sn
        q[:, half:] = qh_ * sn + qh2 * cs
        kh_, kh2 = k[:, :half].copy(), k[:, half:].copy()
        k[:, :half] = kh_ * cs - kh2 * sn
        k[:, half:] = kh_ * sn + kh2 * cs
        if verbose_cp:
            emit(pos, "Q_ROPE", q.reshape(-1), layer=layer)
            emit(pos, "K_ROPE", k.reshape(-1), layer=layer)

        kcache[layer, :, pos, :] = k
        vcache[layer, :, pos, :] = v
        if verbose_cp:
            emit_kv(pos, layer,
                    kcache[layer, :, pos, :].reshape(-1),
                    vcache[layer, :, pos, :].reshape(-1), head_dim)

        # attention over positions 0..pos (vectorized)
        scale = 1.0 / np.sqrt(head_dim)
        q64 = q.astype(np.float64)
        k64 = kcache[layer, :, :pos + 1, :].astype(np.float64)
        v64 = vcache[layer, :, :pos + 1, :].astype(np.float64)
        kv_idx = np.arange(NH) // group
        scores = np.sum(q64[:, None, :] * k64[kv_idx, :, :], axis=2) * scale
        smax = scores.max(axis=1, keepdims=True)
        e = np.exp(scores - smax)
        probs = e / e.sum(axis=1, keepdims=True)
        if verbose_cp:
            emit(pos, "ATTN_SCORES", scores[0].astype(np.float32), layer=layer)
            emit(pos, "ATTN_PROBS",  probs[0].astype(np.float32), layer=layer)

        attn = np.sum(probs[:, :, None] * v64[kv_idx, :, :],
                      axis=1).astype(np.float32)
        attn_flat = attn.reshape(H)
        if verbose_cp:
            emit(pos, "ATTN_VALUE", attn_flat, layer=layer)

        ao = gemv(wl["o"], attn_flat)
        if verbose_cp:
            emit(pos, "O_PROJ", ao, layer=layer)

        x = x + ao
        if verbose_cp:
            emit(pos, "ATTN_RESIDUAL", x, layer=layer)

        # --- FFN branch ---
        xn2 = rmsnorm(x, wl["fn"])
        if verbose_cp:
            emit(pos, "FFN_NORM", xn2, layer=layer)

        g = gemv(wl["g"], xn2)
        u = gemv(wl["u"], xn2)
        if verbose_cp:
            emit(pos, "FFN_GATE", g, layer=layer)
            emit(pos, "FFN_UP",   u, layer=layer)

        act = silu(g) * u
        if verbose_cp:
            emit(pos, "SWIGLU", act, layer=layer)

        down = gemv(wl["d"], act)
        if verbose_cp:
            emit(pos, "FFN_DOWN", down, layer=layer)

        h = x + down
        if verbose_cp:
            emit(pos, "LAYER_RESIDUAL", h, layer=layer)

        # free layer weights immediately
        del wl, q, k, v, xn, q64, k64, v64, scores, e, probs, attn, attn_flat
        del ao, xn2, g, u, act, down, x

    hn = rmsnorm(h, fn_w)
    if verbose_cp:
        emit(pos, "FINAL_NORM", hn)
    return hn

# ---------------------------------------------------------------------------
# resume from checkpoint if present
start_pos = 0
tok = TOKEN_ID
resume = load_checkpoint()
if resume:
    start_pos, tok = resume
    print(f"RESUMING from checkpoint: pos={start_pos} tok={tok}", flush=True)
else:
    print("starting fresh...", flush=True)

TEACHER_TOKENS = [750, 220, 1887, 3932, 262, 1173, 445]
generated = []
for pos in range(start_pos, NPOS):
    print(f"forward pos={pos} tok={tok}", flush=True)
    hn = forward(tok, pos, verbose_cp=(pos == 6))
    logits = logits_top10_from(hn)
    emit_top10(pos, logits)
    generated.append(int(np.argmax(logits)))
    if pos + 1 < len(TEACHER_TOKENS):
        # teacher-force the next position from the frozen common trajectory
        tok = TEACHER_TOKENS[pos + 1]
    else:
        tok = int(np.argmax(logits))
    print(f"step {pos}: next_tok={tok}", flush=True)
    save_checkpoint(pos + 1, tok)

print(f"REFERENCE_MULTITOKEN_DONE tokens={generated} npos={NPOS}")