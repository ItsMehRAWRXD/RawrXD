# q8k_activation_test.py -- is the llama.cpp-vs-numpy divergence explained by
# llama.cpp's Q8_K activation quantization inside its K-quant vec-dot?
#
# For K-quant weights (Q4_K / Q6_K), ggml's mul_mat quantizes the f32
# activation vector to Q8_K (256-element blocks, fp16 scale d = amax/127)
# before the integer dot product.  This script reproduces that protocol in
# numpy and scores it against real llama.cpp (llama-cpp-python binding).
import numpy as np
import gguf
from llama_cpp import Llama

MODEL = r"F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf"
BASE = r"F:\rawrxd\evidence\PARITY_2026-10-13"
TOKENS = [750, 220, 1887, 3932, 262, 1173, 445, 1, 11, 100, 1000, 44]

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


def load(name):
    t = T[name]
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
    return v.reshape(rows, shape[0]), qtype.name


def vec(name):
    t = T[name]
    with open(MODEL, "rb") as fh:
        fh.seek(int(t.data_offset))
        n = int(np.prod([int(x) for x in t.shape]))
        return np.frombuffer(fh.read(n * 4), dtype=np.float32).copy()


print("loading weights ...", flush=True)
LW = []
for layer in range(L):
    p = f"blk.{layer}."
    LW.append({
        "q": load(p + "attn_q.weight")[0], "k": load(p + "attn_k.weight")[0],
        "v": load(p + "attn_v.weight")[0], "o": load(p + "attn_output.weight")[0],
        "g": load(p + "ffn_gate.weight")[0], "u": load(p + "ffn_up.weight")[0],
        "d": load(p + "ffn_down.weight")[0],
        "an": vec(p + "attn_norm.weight"), "fn": vec(p + "ffn_norm.weight"),
        "bq": vec(p + "attn_q.bias"), "bk": vec(p + "attn_k.bias"),
        "bv": vec(p + "attn_v.bias")})
print("  done", flush=True)

EMB_T = T["token_embd.weight"]
EMB_BV, EMB_BS = gguf.GGML_QUANT_SIZES[EMB_T.tensor_type]
EMB_NBPR = (H + EMB_BV - 1) // EMB_BV
EMB_RB = EMB_NBPR * EMB_BS
LM_T = T["token_embd.weight"]
LM_BV, LM_BS = gguf.GGML_QUANT_SIZES[LM_T.tensor_type]
LM_NBPR = (H + LM_BV - 1) // LM_BV
LM_RB = LM_NBPR * LM_BS
LM_ROWS = int(np.prod([int(x) for x in LM_T.shape[1:]]))
FN_W = vec("output_norm.weight")


def emb_row(tok):
    with open(MODEL, "rb") as fh:
        fh.seek(int(EMB_T.data_offset) + tok * EMB_RB)
        raw = fh.read(EMB_RB)
    blk = np.frombuffer(raw, np.uint8).reshape(EMB_NBPR, EMB_BS)
    return np.asarray(gguf.quants.dequantize(blk, EMB_T.tensor_type),
                      dtype=np.float32).reshape(-1)[:H].copy()


# ---- llama.cpp emulated quantized GEMV -----------------------------------
def q8k_quantize(x):
    """Replicate ggml's quantize_row_q8_K for one 256-element block set."""
    x = np.asarray(x, dtype=np.float32)
    n = x.size
    nb = (n + 255) // 256
    pad = nb * 256 - n
    if pad:
        x = np.concatenate([x, np.zeros(pad, dtype=np.float32)])
    xb = x.reshape(nb, 256)
    amax = np.abs(xb).max(axis=1)
    d = (amax / 127.0).astype(np.float32)
    d_g = d.astype(np.float32)
    inv = 1.0 / np.where(d_g == 0, 1.0, d_g)
    q = np.clip(np.rint(xb * inv[:, None]), -127, 127).astype(np.int8)
    return q.astype(np.float32), d_g[:, None]


def gemv_native(W, x):
    return W @ x


def gemv_q8k(W, x):
    """W must be f32 already-dequantised; emulate the K-quant vec_dot."""
    rows, cols = W.shape
    q, d = q8k_quantize(x)
    nblk = q.shape[0]
    qf = q.reshape(-1)[:cols].astype(np.float64)
    rep = np.repeat(d, 256)[:cols]
    Wq = W * rep[None, :]
    return (Wq.astype(np.float64) @ qf).astype(np.float32)


def rms(x, g):
    return (x / np.sqrt(np.mean(x.astype(np.float64) ** 2) + EPS) * g).astype(
        np.float32)


def rope(t):
    cs, sn = np.cos(0.0), np.sin(0.0)   # pos 0 -> identity
    return t


def forward(tok, gemv):
    h = emb_row(tok)
    for layer in range(L):
        w = LW[layer]
        x = h
        xn = rms(x, w["an"])
        q = gemv(w["q"], xn) + w["bq"]
        k = gemv(w["k"], xn) + w["bk"]
        v = gemv(w["v"], xn) + w["bv"]
        attn = v.reshape(NKH, HD)[np.arange(NH) // GROUP].reshape(-1)
        ao = gemv(w["o"], attn)
        x = x + ao
        xn2 = rms(x, w["fn"])
        g = gemv(w["g"], xn2)
        u = gemv(w["u"], xn2)
        act = (g / (1.0 + np.exp(-g.astype(np.float64)))).astype(
            np.float32) * u
        h = x + gemv(w["d"], act)
    hn = rms(h, FN_W)
    out = np.empty(LM_ROWS, dtype=np.float32)
    hn64 = hn.astype(np.float64)
    with open(MODEL, "rb") as fh:
        for r0 in range(0, LM_ROWS, 4096):
            r1 = min(r0 + 4096, LM_ROWS)
            fh.seek(int(LM_T.data_offset) + r0 * LM_RB)
            raw = fh.read((r1 - r0) * LM_RB)
            blk = np.frombuffer(raw, np.uint8).reshape((r1 - r0) * LM_NBPR,
                                                        LM_BS)
            deq = np.asarray(gguf.quants.dequantize(blk, LM_T.tensor_type),
                             dtype=np.float32).reshape(r1 - r0, H)
            out[r0:r1] = gemv(deq, hn)
            del blk, deq
    return out


print("loading llama.cpp ...", flush=True)
llm = Llama(model_path=MODEL, n_ctx=8, n_batch=8, n_threads=8,
            n_gpu_layers=0, logits_all=True, vocab_only=False, verbose=False)

print(f"\n{'tok':>6} {'exact_cos':>10} {'q8k_cos':>9} {'llama_am':>5} "
      f"{'exact_am':>9} {'q8k_am':>7}")
for tok in TOKENS:
    llm.reset()
    llm.eval([tok])
    sx = np.asarray(llm.scores, dtype=np.float32)[0]
    nv = np.rint(gemv_native(np.eye(1), np.zeros(1))).sum()  # keep flake8 calm
    le = forward(tok, gemv_native)
    lq = forward(tok, gemv_q8k)

    def cos(a, b):
        a = a.astype(np.float64)
        b = b.astype(np.float64)
        return float(a @ b / (np.linalg.norm(a) * np.linalg.norm(b)))

    print(f"{tok:>6} {cos(le, sx):10.5f} {cos(lq, sx):9.5f} "
          f"{int(np.argmax(sx)):>5} {int(np.argmax(le)):>9} "
          f"{int(np.argmax(lq)):>7}", flush=True)
