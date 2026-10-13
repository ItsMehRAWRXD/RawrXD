# bias_policy_scan.py -- which bias policy does llama.cpp actually use?
#
# Two independent implementations (ref_multitoken_tied.py and this clean-room
# forward built only on gguf.quants.dequantize) both give argmax 5290 at
# position 0, while real llama.cpp gives 304.  Positions 1..6 agree to
# cosine ~0.997, so the forward math is right in general.
#
# This scans bias policies x positions and scores each against the real
# llama.cpp logits, so the policy llama.cpp implements is identified by
# evidence rather than assumption.
import numpy as np
import gguf

MODEL = r"F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf"
BASE = r"F:\rawrxd\evidence\PARITY_2026-10-13"
TEACHER = [750, 220, 1887, 3932, 262, 1173, 445]
NPOS = len(TEACHER)

reader = gguf.GGUFReader(MODEL)
T = {t.name: t for t in reader.tensors}


def fraw(k):
    f = reader.fields[k]
    return np.asarray(f.parts[f.data[0]]).reshape(-1)


def fv(k):
    return int(fraw(k)[0])


H = fv("qwen2.embedding_length")
L = fv("qwen2.block_count")
NH = fv("qwen2.attention.head_count")
NKH = fv("qwen2.attention.head_count_kv")
EPS = float(fraw("qwen2.attention.layer_norm_rms_epsilon")[0])
THETA = fv("qwen2.rope.freq_base")
HD = H // NH
GROUP = NH // NKH
HALF = HD // 2
INV_F = THETA ** (-np.arange(HALF, dtype=np.float64) / HALF)

# ---- preload every layer weight once (about 190 MB as float32) ----------
print("dequantising layer weights ...", flush=True)
LW = []
for layer in range(L):
    p = f"blk.{layer}."

    def w(name):
        t = T[p + name]
        qtype = t.tensor_type
        shape = [int(x) for x in t.shape]
        rows = int(np.prod(shape[1:]))
        bv, bs = gguf.GGML_QUANT_SIZES[qtype]
        nbpr = (shape[0] + bv - 1) // bv
        rb = nbpr * bs
        with open(MODEL, "rb") as fh:
            fh.seek(int(t.data_offset))
            raw = fh.read(rows * rb)
        blk = np.frombuffer(raw, np.uint8).reshape(rows * nbpr, bs)
        v = np.asarray(gguf.quants.dequantize(blk, qtype), dtype=np.float32)
        return v.reshape(rows, shape[0])

    def b(name):
        t = T.get(p + name)
        if t is None:
            return None
        with open(MODEL, "rb") as fh:
            fh.seek(int(t.data_offset))
            n = int(np.prod([int(x) for x in t.shape]))
            return np.frombuffer(fh.read(n * 4), dtype=np.float32).copy()

    LW.append(dict(
        q=w("attn_q.weight"), k=w("attn_k.weight"), v=w("attn_v.weight"),
        o=w("attn_output.weight"), g=w("ffn_gate.weight"),
        u=w("ffn_up.weight"), d=w("ffn_down.weight"),
        an=b("attn_norm.weight"), fn=b("ffn_norm.weight"),
        bq=b("attn_q.bias"), bk=b("attn_k.bias"), bv_=b("attn_v.bias")))
print("  done", flush=True)

# embedding rows (only the tokens we need) and the final norm
emb_t = T["token_embd.weight"]
emb_bv, emb_bs = gguf.GGML_QUANT_SIZES[emb_t.tensor_type]
EMB_NBPR = (H + emb_bv - 1) // emb_bv
EMB_RB = EMB_NBPR * emb_bs


def emb_row(tok):
    with open(MODEL, "rb") as fh:
        fh.seek(int(emb_t.data_offset) + tok * EMB_RB)
        raw = fh.read(EMB_RB)
    blk = np.frombuffer(raw, np.uint8).reshape(EMB_NBPR, emb_bs)
    return np.asarray(gguf.quants.dequantize(blk, emb_t.tensor_type),
                      dtype=np.float32).reshape(-1)[:H].copy()


fn_t = T["output_norm.weight"]
with open(MODEL, "rb") as fh:
    fh.seek(int(fn_t.data_offset))
    FN_W = np.frombuffer(fh.read(H * 4), dtype=np.float32).copy()


def rms(x, g):
    return (x / np.sqrt(np.mean(x.astype(np.float64) ** 2) + EPS) * g).astype(
        np.float32)


def rope(t, pos):
    ang = pos * INV_F
    cs, sn = np.cos(ang), np.sin(ang)
    t = t.reshape(-1, HD)
    a = t[:, :HALF].copy()
    b = t[:, HALF:].copy()
    out = np.empty_like(t)
    out[:, :HALF] = a * cs - b * sn
    out[:, HALF:] = a * sn + b * cs
    return out


def lm_logits(hn):
    lm = T["token_embd.weight"]
    bv, bs = gguf.GGML_QUANT_SIZES[lm.tensor_type]
    nbpr = (H + bv - 1) // bv
    rb = nbpr * bs
    rows = int(np.prod([int(x) for x in lm.shape[1:]]))
    out = np.empty(rows, dtype=np.float32)
    hn64 = hn.astype(np.float64)
    with open(MODEL, "rb") as fh:
        for r0 in range(0, rows, 4096):
            r1 = min(r0 + 4096, rows)
            fh.seek(int(lm.data_offset) + r0 * rb)
            raw = fh.read((r1 - r0) * rb)
            blk = np.frombuffer(raw, np.uint8).reshape((r1 - r0) * nbpr, bs)
            deq = np.asarray(gguf.quants.dequantize(blk, lm.tensor_type),
                             dtype=np.float64).reshape(r1 - r0, H)
            out[r0:r1] = (deq @ hn64).astype(np.float32)
            del blk, deq
    return out


def forward(tokens, policy):
    """policy: subset of {'q','k','v'} whose biases are applied."""
    kcache = [np.zeros((NKH, NPOS, HD), dtype=np.float32) for _ in range(L)]
    vcache = [np.zeros((NKH, NPOS, HD), dtype=np.float32) for _ in range(L)]
    logits = []
    for pos in range(len(tokens)):
        h = emb_row(tokens[pos])
        for layer in range(L):
            w = LW[layer]
            x = h
            xn = rms(x, w["an"])
            q = w["q"] @ xn
            k = w["k"] @ xn
            v = w["v"] @ xn
            if "q" in policy:
                q = q + w["bq"]
            if "k" in policy:
                k = k + w["bk"]
            if "v" in policy:
                v = v + w["bv_"]
            q = rope(q.reshape(NH, HD), pos)
            k = rope(k.reshape(NKH, HD), pos)
            v = v.reshape(NKH, HD)
            kcache[layer][:, pos, :] = k
            vcache[layer][:, pos, :] = v
            K = kcache[layer][:, :pos + 1, :].astype(np.float64)
            V = vcache[layer][:, :pos + 1, :].astype(np.float64)
            q64 = q.astype(np.float64)
            idx = np.arange(NH) // GROUP
            sc = np.sum(q64[:, None, :] * K[idx], axis=2) / np.sqrt(HD)
            sc = sc - sc.max(axis=1, keepdims=True)
            e = np.exp(sc)
            pr = e / e.sum(axis=1, keepdims=True)
            attn = np.sum(pr[:, :, None] * V[idx], axis=1).reshape(-1)
            ao = w["o"] @ attn
            x = x + ao
            xn2 = rms(x, w["fn"])
            g = w["g"] @ xn2
            u = w["u"] @ xn2
            act = (g / (1.0 + np.exp(-g.astype(np.float64)))).astype(
                np.float32) * u
            h = x + (w["d"] @ act)
        hn = rms(h, FN_W)
        logits.append(lm_logits(hn))
    return logits


def score(a, b):
    a64 = a.astype(np.float64)
    b64 = b.astype(np.float64)
    cos = float(a64 @ b64 / (np.linalg.norm(a64) * np.linalg.norm(b64)))
    rmse = float(np.sqrt(np.mean((a64 - b64) ** 2)))
    return cos, rmse, int(np.argmax(a)), int(np.argmax(b))


llama = [np.fromfile(rf"{BASE}\llama_truth\ref_logits_pos{p}.bin",
                     dtype="<f4") for p in range(NPOS)]

POLICIES = [
    ("all(q,k,v)", frozenset("qkv")),
    ("none       ", frozenset()),
    ("k_only     ", frozenset("k")),
    ("v_only     ", frozenset("v")),
    ("q_only     ", frozenset("q")),
    ("qk         ", frozenset("qk")),
    ("qv         ", frozenset("qv")),
    ("kv         ", frozenset("kv")),
]
print(f"\n{'policy':<13} " + " ".join(f"pos{p:<1}(cos/argmax_match)" for p in []))
for name, pol in POLICIES:
    lg = forward(TEACHER, pol)
    cells = []
    ok = 0
    for p in range(NPOS):
        c, r, na, nb = score(lg[p], llama[p])
        m = "Y" if na == nb else "N"
        if na == nb:
            ok += 1
        cells.append(f"p{p}:{c:+.4f}{m}")
    print(f"{name}  " + " ".join(cells) + f"   argmax_match={ok}/{NPOS}")
