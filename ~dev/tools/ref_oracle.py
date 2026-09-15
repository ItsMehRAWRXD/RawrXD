# DEEP2_QWEN25_LAYER0_LOGIT_PARITY_001 — Python reference oracle (v2)
#
# Independent Qwen2.5 forward for ONE token at position 0, emitting the same
# fingerprint format as the Deep2 C++ parity probe so the two traces can be
# diffed checkpoint-by-checkpoint:
#   STEP=<name> COUNT=<n> MIN=<v> MAX=<v> MEAN=<v> L2=<v>
#   FIRST8=<a,...,h> HASH=<fnv1a64-hex>
#
# Weights dequantized in vectorized NumPy from raw GGUF bytes parsed with an
# in-house parser. GEMV runs in float64 accumulation, chunked over rows.
#
# Usage: python ref_oracle.py <model.gguf> <tokenId> [topN] [--layer0]
import struct
import sys
import numpy as np

MODEL = sys.argv[1] if len(sys.argv) > 1 else \
    r"F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf"
TOKEN_ID = int(sys.argv[2]) if len(sys.argv) > 2 else 750  # "def"
TOPN = int(sys.argv[3]) if len(sys.argv) > 3 else 10
ONLY_LAYER0 = "--layer0" in sys.argv

TYPE_Q4_K, TYPE_Q6_K, TYPE_F32 = 12, 14, 0
BLOCK_VALS = 256

# ---------------------------------------------------------------------------
# GGUF header parsing (metadata value type is u32!)
# ---------------------------------------------------------------------------
def read_header_kv(path):
    meta = {}
    with open(path, "rb") as fh:
        magic, version, tcount, kvcount = struct.unpack("<4sIQQ", fh.read(24))
        assert magic == b"GGUF", magic
        for _ in range(kvcount):
            klen = struct.unpack("<Q", fh.read(8))[0]
            key = fh.read(klen).decode("utf-8", "replace")
            vtype = struct.unpack("<I", fh.read(4))[0]  # u32 per GGUF spec
            val, fh = _read_val(fh, vtype)
            meta[key] = val
        hdr_end = fh.tell()
    return meta, tcount, hdr_end

def _read_val(fh, vtype):
    if vtype == 8:  # string
        n = struct.unpack("<Q", fh.read(8))[0]
        return fh.read(n).decode("utf-8", "replace"), fh
    if vtype == 9:  # array
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
        if etype not in fmtc:
            raise RuntimeError(f"unsupported array elem type {etype}")
        c, esz = fmtc[etype]
        return list(struct.unpack(f"<{count}{c}", fh.read(esz * count))), fh
    fmtc = {0:("B",1),1:("b",1),2:("H",2),3:("h",2),4:("I",4),5:("i",4),
            6:("f",4),7:("?",1),10:("Q",8),11:("q",8),12:("d",8)}
    c, esz = fmtc[vtype]
    return struct.unpack(f"<{c}", fh.read(esz))[0], fh

# ---------------------------------------------------------------------------
# Dequantization (vectorized, ggml reference semantics)
# ---------------------------------------------------------------------------
KMASK1, KMASK2, KMASK3 = 0x3F3F3F3F, 0x0F0F0F0F, 0x03030303

def dequant_q4_k_vec(src):
    """src: [nb, 144] uint8 -> [nb*256] float32 (ggml dequantize_row_q4_K)."""
    nb = src.shape[0]
    d = src[:, 0:2].copy().view(np.float16).astype(np.float32)          # [nb,1]
    dmin = src[:, 2:4].copy().view(np.float16).astype(np.float32)       # [nb,1]
    utmp = np.zeros((nb, 4), dtype=np.uint32)
    utmp[:, 0:3] = src[:, 4:16].copy().view(np.uint32)
    utmp[:, 3] = ((utmp[:, 2] >> 4) & KMASK2) | (((utmp[:, 1] >> 6) & KMASK3) << 4)
    uaux = utmp[:, 1] & KMASK1
    utmp[:, 1] = (utmp[:, 2] & KMASK2) | (((utmp[:, 0] >> 6) & KMASK3) << 4)
    utmp[:, 2] = uaux
    utmp[:, 0] &= KMASK1
    packed = utmp.view(np.uint8)                                        # [nb, 16]
    sc = packed[:, 0:8].astype(np.float32)                              # [nb, 8]
    mn = packed[:, 8:16].astype(np.float32)                             # [nb, 8]
    qs = src[:, 16:144]                                                 # [nb, 128]
    out = np.empty((nb, BLOCK_VALS), dtype=np.float32)
    # ggml reference: 4 groups of 64 values; sc[is]/sc[is+1] per group
    for g in range(4):
        j = g * 64
        is_ = g * 2
        q = qs[:, g * 32:(g + 1) * 32]                                  # [nb, 32]
        lo = (q & 0x0F).astype(np.float32)                              # [nb, 32]
        hi = (q >> 4).astype(np.float32)                                # [nb, 32]
        out[:, j:j + 32] = d * sc[:, is_:is_ + 1] * lo - dmin * mn[:, is_:is_ + 1]
        out[:, j + 32:j + 64] = d * sc[:, is_ + 1:is_ + 2] * hi \
            - dmin * mn[:, is_ + 1:is_ + 2]
    return out.reshape(-1)

def dequant_q6_k_vec(src):
    """src: [nb, 210] uint8 -> [nb*256] float32 (ggml dequantize_row_q6_K)."""
    nb = src.shape[0]
    ql = src[:, 0:128]
    qh = src[:, 128:192]
    scales = src[:, 192:208].copy().view(np.int8).astype(np.float32)    # [nb, 16]
    d = src[:, 208:210].copy().view(np.float16).astype(np.float32)      # [nb,1]
    w = np.empty((nb, BLOCK_VALS), dtype=np.int32)
    for jj in range(2):          # two 128-value chunks
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
    dexp = np.repeat(d * scales, 16, axis=1)                            # [nb, 256]
    return (dexp * w).reshape(-1)

# ---------------------------------------------------------------------------
# Fingerprint emission (matches C++ Deep2Engine parity probe)
# ---------------------------------------------------------------------------
def fnv1a_hash_f32(v):
    h = 1469598103934665603
    b = np.ascontiguousarray(v, dtype=np.float32).tobytes()
    for byte in b:
        h ^= byte
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h

def emit(step, v):
    v = np.asarray(v, dtype=np.float32)
    n = v.size
    finite = np.isfinite(v)
    nf = int(finite.sum())
    fv = v[finite].astype(np.float64)
    if nf:
        mn, mx = float(fv.min()), float(fv.max())
        mean = float(fv.sum() / nf)
        l2 = float(np.sqrt(np.sum(fv * fv)))
    else:
        mn = mx = mean = l2 = 0.0
    f8 = np.asarray(v[:8], dtype=np.float64).ravel()
    f8s = ",".join(f"{x:.9g}" for x in f8)
    print(f"STEP={step} COUNT={n} MIN={mn:.9g} MAX={mx:.9g} MEAN={mean:.9g} "
          f"L2={l2:.9g} FIRST8={f8s} HASH={fnv1a_hash_f32(v):016x}", flush=True)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
print("parsing header...", flush=True)
meta, tcount, hdr_end = read_header_kv(MODEL)
arch = meta.get("general.architecture", "qwen2")
alignment = int(meta.get("general.alignment", 32))

H = int(meta[f"{arch}.embedding_length"])
L = int(meta[f"{arch}.block_count"])
NH = int(meta[f"{arch}.attention.head_count"])
NKH = int(meta[f"{arch}.attention.head_count_kv"])
FFN = int(meta[f"{arch}.feed_forward_length"])
EPS = float(meta[f"{arch}.attention.layer_norm_rms_epsilon"])
THETA = float(meta.get(f"{arch}.rope.freq_base", 10000.0))
print(f"ARCH={arch} H={H} L={L} HEADS={NH} KV_HEADS={NKH} HEAD_DIM={H//NH} "
      f"GQA_GROUP={NH//NKH} FFN_DIM={FFN} ROPE_THETA={THETA:g} ROPE_NEOX=1 "
      f"RMS_EPS={EPS:g} Q_BIAS=present K_BIAS=present V_BIAS=present", flush=True)

# tensor directory: walk AFTER metadata (value-type u32 keeps us aligned)
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

# data section base is aligned AFTER header + metadata + tensor infos
dir_end = f.tell()
data_start = (dir_end + alignment - 1) // alignment * alignment
print(f"data_start=0x{data_start:X} (dir_end=0x{dir_end:X})", flush=True)

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
    """Full [rows, cols] float32, GGUF dims[0]=cols (fastest)."""
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
        return v.astype(np.float32)          # 1-D tensor (norms, biases)
    return v.reshape(rows, cols).astype(np.float32)

def gemv(w, x, chunk=4096):
    """y = W @ x with float64 accumulation, row-chunked to bound memory."""
    rows, cols = w.shape
    out = np.empty(rows, dtype=np.float32)
    x64 = x.astype(np.float64)
    for r0 in range(0, rows, chunk):
        r1 = min(r0 + chunk, rows)
        out[r0:r1] = (w[r0:r1].astype(np.float64) @ x64).astype(np.float32)
    return out

def rmsnorm(x, w):
    ss = float(np.sum(x.astype(np.float64) ** 2))
    inv = 1.0 / np.sqrt(ss / len(x) + EPS)
    return (x * inv * w).astype(np.float32)

def silu(x):
    return (x / (1.0 + np.exp(-x.astype(np.float64)))).astype(np.float32)

# Embedding row: only TOKEN_ID row is dequantized
dims, ttype, toff = tinfo["token_embd.weight"]
VOCAB = dims[1]
nb_per_row = (dims[0] + BLOCK_VALS - 1) // BLOCK_VALS
row_bytes = nb_per_row * BLOCK_BYTES[TYPE_Q4_K]
f.seek(data_start + toff + TOKEN_ID * row_bytes)
row_raw = f.read(row_bytes)
emb_row = dequant_q4_k_vec(
    np.frombuffer(row_raw, dtype=np.uint8).reshape(nb_per_row, 144))[:H]
h = emb_row.copy()
emit("EMBED", h)

head_dim = H // NH
kv_dim = NKH * head_dim
half = head_dim // 2
group = NH // NKH

for layer in range(L):
    p = f"blk.{layer}."
    x = h
    xn = rmsnorm(x, deq_mat(p + "attn_norm.weight"))
    if layer == 0:
        emit("ATTN_NORM", xn)

    q = gemv(deq_mat(p + "attn_q.weight"), xn) \
        + np.frombuffer(read_raw(p + "attn_q.bias")[0], dtype=np.float32)
    k = gemv(deq_mat(p + "attn_k.weight"), xn) \
        + np.frombuffer(read_raw(p + "attn_k.bias")[0], dtype=np.float32)
    v = gemv(deq_mat(p + "attn_v.weight"), xn) \
        + np.frombuffer(read_raw(p + "attn_v.bias")[0], dtype=np.float32)
    if layer == 0:
        emit("Q", q); emit("K", k); emit("V", v)

    q = q.reshape(NH, head_dim)
    k = k.reshape(NKH, head_dim)
    v = v.reshape(NKH, head_dim)

    pos = 0
    inv_f = THETA ** (-np.arange(half, dtype=np.float64) / half)
    ang = pos * inv_f
    cs, sn = np.cos(ang), np.sin(ang)
    # NeoX: pair (i, i+half); at pos 0 angle=0 -> identity, but compute anyway
    qh_, qh2 = q[:, :half], q[:, half:]
    q[:, :half] = qh_ * cs - qh2 * sn
    q[:, half:] = qh_ * sn + qh2 * cs
    kh_, kh2 = k[:, :half], k[:, half:]
    k[:, :half] = kh_ * cs - kh2 * sn
    k[:, half:] = kh_ * sn + kh2 * cs
    if layer == 0:
        emit("Q_ROPE", q.reshape(-1)); emit("K_ROPE", k.reshape(-1))

    # position 0: softmax singleton -> attention out = v[0] per group
    attn_out = np.repeat(v, group, axis=0)          # [NH, head_dim]
    attn_flat = attn_out.reshape(H)
    if layer == 0:
        s0 = float(np.dot(q[0].astype(np.float64), k[0].astype(np.float64)))
        emit("ATTN_SCORES", np.array([s0 * (1.0 / np.sqrt(head_dim))]))
        emit("ATTN_PROBS", np.array([1.0]))
        emit("ATTN_VALUE", attn_flat)

    ao = gemv(deq_mat(p + "attn_output.weight"), attn_flat)
    if layer == 0:
        emit("O_PROJ", ao)
    x = x + ao
    if layer == 0:
        emit("ATTN_RESIDUAL", x)

    xn2 = rmsnorm(x, deq_mat(p + "ffn_norm.weight"))
    if layer == 0:
        emit("FFN_NORM", xn2)
    g = gemv(deq_mat(p + "ffn_gate.weight"), xn2)
    u = gemv(deq_mat(p + "ffn_up.weight"), xn2)
    if layer == 0:
        emit("FFN_GATE", g); emit("FFN_UP", u)
    act = silu(g) * u
    if layer == 0:
        emit("SWIGLU", act)
    down = gemv(deq_mat(p + "ffn_down.weight"), act)
    if layer == 0:
        emit("FFN_DOWN", down)
    h = x + down
    if layer == 0:
        emit("LAYER_RESIDUAL", h)
    print(f"layer {layer}: |h|={float(np.linalg.norm(h.astype(np.float64))):.4f} "
          f"h[0:4]={np.array2string(h[:4], precision=4)}", flush=True)
    if ONLY_LAYER0:
        print("ONLY_LAYER0=1 stopping after layer 0", flush=True)
        break

if ONLY_LAYER0:
    print("REFERENCE_LAYER0_DONE", flush=True)
    sys.exit(0)

hn = rmsnorm(h, deq_mat("output_norm.weight"))
emit("FINAL_NORM", hn)

# LM head chunked (output.weight is Q6_K: 210B per 256 values)
dims, ttype, toff = tinfo["output.weight"]
cols = dims[0]
rows = int(np.prod(dims[1:]))
nb_per_row_lm = (cols + BLOCK_VALS - 1) // BLOCK_VALS
row_bytes_lm = nb_per_row_lm * BLOCK_BYTES[TYPE_Q6_K]
logits = np.empty(rows, dtype=np.float32)
hn64 = hn.astype(np.float64)
CH = 8192
for r0 in range(0, rows, CH):
    r1 = min(r0 + CH, rows)
    f.seek(data_start + toff + r0 * row_bytes_lm)
    raw = f.read((r1 - r0) * row_bytes_lm)
    blk = np.frombuffer(raw, dtype=np.uint8).reshape(r1 - r0, nb_per_row_lm, 210)
    deq = dequant_q6_k_vec(blk.reshape((r1 - r0) * nb_per_row_lm, 210)) \
        .reshape(r1 - r0, cols)
    logits[r0:r1] = (deq.astype(np.float64) @ hn64).astype(np.float32)
    del blk, deq

emit("LOGITS", logits)
idx = np.argsort(-logits)[:TOPN]
print(f"TOP{TOPN}_TOKENS")
for i in idx:
    print(f"{int(i)} {logits[i]:.6f}")
print(f"REFERENCE_DONE top1={int(idx[0])} logit={logits[idx[0]]:.6f}")