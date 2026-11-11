# cleanroom_pos0.py -- fully independent Qwen2 forward pass at position 0,
# written against the authoritative gguf package dequantizers only (no code
# shared with ref_multitoken_tied.py).  Settles whether llama.cpp or the numpy
# reference is right at position 0.
import numpy as np
import gguf

MODEL = r"F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf"
TOK = 750

reader = gguf.GGUFReader(MODEL)
T = {t.name: t for t in reader.tensors}


def fraw(key):
    f = reader.fields[key]
    return np.asarray(f.parts[f.data[0]])


def fv(key):
    return int(fraw(key).reshape(-1)[0])


H = fv("qwen2.embedding_length")
L = fv("qwen2.block_count")
NH = fv("qwen2.attention.head_count")
NKH = fv("qwen2.attention.head_count_kv")
EPS = float(fraw("qwen2.attention.layer_norm_rms_epsilon").reshape(-1)[0])
THETA = fv("qwen2.rope.freq_base")
print(f"H={H} L={L} NH={NH} NKH={NKH} EPS={EPS} THETA={THETA}")

HD = H // NH
NFF = fv("qwen2.feed_forward_length")


def w(name, nrows=None):
    t = T[name]
    qtype = t.tensor_type
    shape = [int(x) for x in t.shape]
    rows = int(np.prod(shape[1:]))
    if nrows is not None:
        rows = min(rows, nrows)
    bv, bs = gguf.GGML_QUANT_SIZES[qtype]
    nbpr = (shape[0] + bv - 1) // bv
    rb = nbpr * bs
    with open(MODEL, "rb") as fh:
        fh.seek(int(t.data_offset))
        raw = fh.read(rows * rb)
    blk = np.frombuffer(raw, np.uint8).reshape(rows * nbpr, bs)
    v = np.asarray(gguf.quants.dequantize(blk, qtype), dtype=np.float32)
    return v.reshape(rows, shape[0])


def vec(name):
    t = T[name]
    with open(MODEL, "rb") as fh:
        fh.seek(int(t.data_offset))
        n = int(np.prod([int(x) for x in t.shape]))
        raw = fh.read(n * 4)
    return np.frombuffer(raw, dtype=np.float32).copy()


# --- embedding row for TOK ---
emb = w("token_embd.weight", nrows=TOK + 1)[TOK].copy()
print(f"EMBED L2={np.linalg.norm(emb.astype(np.float64)):.9g} "
      f"FIRST8={','.join(f'{x:.9g}' for x in emb[:8])}")

fn_w = vec("output_norm.weight")


def rms(x, g):
    return (x / np.sqrt(np.mean(x.astype(np.float64) ** 2) + EPS) * g).astype(
        np.float32)


half = HD // 2
inv_f = THETA ** (-np.arange(half, dtype=np.float64) / half)
cs, sn = np.cos(0.0 * inv_f), np.sin(0.0 * inv_f)

h = emb
for layer in range(L):
    p = f"blk.{layer}."
    xn = rms(h, vec(p + "attn_norm.weight"))
    q = w(p + "attn_q.weight") @ xn + vec(p + "attn_q.bias")
    k = w(p + "attn_k.weight") @ xn + vec(p + "attn_k.bias")
    v = w(p + "attn_v.weight") @ xn + vec(p + "attn_v.bias")
    q = q.reshape(NH, HD)
    k = k.reshape(NKH, HD)
    v = v.reshape(NKH, HD)
    # pos 0: RoPE is identity
    attn = v[np.arange(NH) // (NH // NKH)].reshape(-1)
    ao = w(p + "attn_output.weight") @ attn
    x = h + ao
    xn2 = rms(x, vec(p + "ffn_norm.weight"))
    g = w(p + "ffn_gate.weight") @ xn2
    u = w(p + "ffn_up.weight") @ xn2
    act = (g / (1.0 + np.exp(-g.astype(np.float64)))).astype(np.float32) * u
    down = w(p + "ffn_down.weight") @ act
    h = x + down
    if layer < 2 or layer == 27:
        print(f"L{layer} attn_resid L2={np.linalg.norm(x.astype('f8')):.6g} "
              f"layer_resid L2={np.linalg.norm(h.astype('f8')):.6g}")

hn = rms(h, fn_w)
print(f"FINAL_NORM L2={np.linalg.norm(hn.astype(np.float64)):.9g} "
      f"FIRST8={','.join(f'{x:.9g}' for x in hn[:8])}")

# --- LM head (tied to token_embd), chunked to bound peak memory ---
lm = T["token_embd.weight"]
lm_bv, lm_bs = gguf.GGML_QUANT_SIZES[lm.tensor_type]
lm_rows = int(np.prod([int(x) for x in lm.shape[1:]]))
lm_nbpr = (H + lm_bv - 1) // lm_bv
lm_rb = lm_nbpr * lm_bs
logits = np.empty(lm_rows, dtype=np.float32)
CH = 4096
with open(MODEL, "rb") as fh:
    fh.seek(int(lm.data_offset))
    for r0 in range(0, lm_rows, CH):
        r1 = min(r0 + CH, lm_rows)
        fh.seek(int(lm.data_offset) + r0 * lm_rb)
        raw = fh.read((r1 - r0) * lm_rb)
        blk = np.frombuffer(raw, np.uint8).reshape((r1 - r0) * lm_nbpr, lm_bs)
        deq = np.asarray(gguf.quants.dequantize(blk, lm.tensor_type),
                         dtype=np.float64).reshape(r1 - r0, H)
        logits[r0:r1] = (deq @ hn.astype(np.float64)).astype(np.float32)
        del blk, deq

top = np.argsort(-logits)[:10]
print("CLEANROOM_POS0 argmax=%d" % int(np.argmax(logits)))
print("CLEANROOM TOP10=" + ",".join(f"{int(i)}:{logits[i]:.6f}" for i in top))

import os
BASE = r"F:\rawrxd\evidence\PARITY_2026-10-13"
logits.astype("<f4").tofile(os.path.join(BASE, "cleanroom_pos0.LOGITS.f32"))
