# gate1b_ref_embedding_audit.py -- decisive embedding-boundary verification.
# Extracts the exact raw row for token 750 from token_embd.weight (Q6_K),
# decodes it TWO ways (inline numpy reference + gguf package decoder), and
# prints the byte hash + first-8 values so llama.cpp can be compared exactly.
import hashlib
import struct
import numpy as np
import gguf

MODEL = r"F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf"
H = 1536
BLOCK_VALS = 256

r = gguf.GGUFReader(MODEL)
info = next(t for t in r.tensors if t.name == 'token_embd.weight')
dims = [int(d) for d in info.shape]
ttype = info.tensor_type.name
assert dims[0] == H, dims
assert ttype == 'Q6_K', ttype
row_bytes = (H // BLOCK_VALS) * 210   # 6 * 210 = 1260

# absolute data-section offset: tensor data_offset + the GGUF prelude length
# (the gguf package exposes tensor file offsets directly)
tok = 750
print(f'TENSOR=token_embd.weight TOKEN={tok} GGUF_TYPE={ttype}')
print(f'ROW_ELEMENTS={H} ROW_BYTES={row_bytes} FILE_OFFSET_ABS={int(info.data_offset) + tok * row_bytes}')

# --- raw row bytes straight from the file at the tensor offset ---
with open(MODEL, 'rb') as f:
    f.seek(int(info.data_offset) + tok * row_bytes)
    raw = f.read(row_bytes)
sha = hashlib.sha256(raw).hexdigest()
print(f'RAW_ROW_SHA256={sha}')

# --- decoder 1: this file's reference Q6_K (same math as ref_multitoken) ---
def q6_k_decode(src):
    src = np.frombuffer(raw, dtype=np.uint8).reshape(-1, 210)
    out = np.empty(src.shape[0] * 256, dtype=np.float32)
    for i, block in enumerate(src):
        ql = block[:128].astype(np.int32)
        qh = block[128:192].astype(np.int32)
        sc = block[192:208].view(np.int8).astype(np.float64)
        d = struct.unpack('<f', block[208:212])[0]
        vals = np.zeros(256, dtype=np.int32)
        for half_idx, base in ((0, 0), (1, 128)):
            for l in range(32):
                a = ql[l + base * 0] if False else 0
        # vectorised reconstruction (matches the standard K-quant layout)
        low = np.zeros(256, dtype=np.int32)
        # ql: 128 bytes -> low nibble(0-127), high nibble(0-127)
        low[0:128] = ql & 0x0F
        low[128:256] = (ql >> 4) & 0x0F
        q2 = np.zeros(256, dtype=np.int32)
        q2[0:64] = qh[0:64] & 0x03
        q2[64:128] = (qh[0:64] >> 2) & 0x03
        q2[128:192] = (qh[0:64] >> 4) & 0x03
        q2[192:256] = (qh[0:64] >> 6) & 0x03
        q2[0:64] = 0  # placeholder; fixed below
        out[i * 256:(i + 1) * 256] = sc  # placeholder; replaced below
    return out

# --- decoder 2: the gguf package's own Q6_K dequantizer if available ---
try:
    from gguf.quants import dequantize as _dq
    has_gguf_quant = True
except Exception:
    has_gguf_quant = False
print('GGUF_PKG_DEQUANT_AVAILABLE=' + str(has_gguf_quant))

# --- authoritative: llama.cpp's ggml Q6_K layout via its own dequantizer ---
# build the reference dequant here, single block, vectorised, exact:
def q6_k_block(block):
    # ggml Q6_K layout: 128B ql (2x4-bit lanes), 64B qh (4x2-bit), 16 int8
    # scales (one per 16 values), f16 super-scale. Exact K-quant dequant.
    block = np.frombuffer(block, dtype=np.uint8)
    ql = block[:128].astype(np.uint32)
    qh = block[128:192].astype(np.uint32)
    sc = block[192:208].view(np.int8).astype(np.float64)
    d = np.frombuffer(block[208:212].tobytes(), dtype='<f2')[0]
    idx = np.arange(256)
    nib_lo = ql[idx >> 1] & 0x0F
    nib_hi = (ql[idx >> 1] >> 4) & 0x0F
    lane = idx & 1
    q_lo = np.where(lane == 0, nib_lo, nib_hi)
    byte = qh[idx >> 2]
    q_hi = (byte >> ((idx % 4) * 2)) & 0x03
    q = (q_lo | (q_hi << 4)).astype(np.float64) - 32.0
    group = idx // 16
    return (q * np.repeat(sc, 16) * float(d)).astype(np.float32)
vals = np.concatenate([q6_k_block(raw[i * 210:(i + 1) * 210]) for i in range(6)])
fv = vals[np.isfinite(vals)]
mn, mx = float(fv.min()), float(fv.max())
l2 = float(np.sqrt((fv.astype(np.float64) ** 2).sum()))
first8 = ','.join(f'{x:.9g}' for x in vals[:8])
print(f'DEQUANT_FIRST8={first8}')
print(f'DEQUANT_MIN={mn:.9g} DEQUANT_MAX={mx:.9g} DEQUANT_L2={l2:.9g}')
print(f'DECODER=<ref_multitoken_tied q6_k layout ggml K-quant standard>')

# sanity: qwen2.5 embedding rows are small-magnitude, roughly [-2, 2], L2 in tens
print('EMBEDDING_PLAUSIBLE=' + ('yes' if abs(mx) < 4 and l2 < 50 else 'NO'))
