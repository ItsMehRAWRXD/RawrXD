#!/usr/bin/env python3
"""
DEFINITIVE: which arithmetic does llama.cpp use for Q3_K GEMV?
Isolate a single GEMV (layer 0 ffn_down, Q3_K) using:
  A) Deep2 integer-dot  (Q3_K weight x Q8_K-quantized input)
  B) F32 dequant        (dequantize weight, F32 multiply-accumulate)
Compare each against the llama.cpp reference ffn_out at L0.

Input = Deep2's own swiglu output at L0 (so any input-quantization effect is
isolated to the GEMV arithmetic itself, matching Deep2's actual input).
"""
import os
import struct
import numpy as np
import gguf

D2 = r"F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone"
REF = r"F:\rawrxd\evidence\deep2_gate_a\ref_intermediate_v2"
MODEL = r"F:\rawrxd\llama3.2-3b-Q2_K.gguf"
QK_K = 256

def load_bin(p):
    with open(p, 'rb') as f:
        return np.frombuffer(f.read(), dtype='<f4').astype(np.float64)

def build_trace(pos):
    m = {}
    with open(os.path.join(D2, f"d2_trace_pos{pos}.txt")) as f:
        for line in f:
            if line.startswith('blk='):
                q = line.strip().split()
                m[(int(q[0].split('=')[1]), q[3].split('=')[1])] = int(q[1].split('=')[1])
    return m

def d2_tensor(pos, layer, name):
    blk = 999 if layer < 0 else layer
    tr = build_trace(pos)
    if (layer, name) not in tr:
        return None
    pc = tr[(layer, name)]
    path = os.path.join(D2, f"d2_pos{pos}_blk{blk}_pc{pc}_{name}.bin")
    return load_bin(path) if os.path.exists(path) else None

def fp16_to_fp32(u16):
    """Exact fp16 -> fp32."""
    return np.frombuffer(struct.pack('<H', int(u16)), dtype=np.float16)[0].astype(np.float64)

# ---- Q3_K dequantization (ggml dequantize_row_q3_K) ----
def dequant_block_q3_K(block, out, base=0):
    """ggml dequantize_row_q3_K: q+=32 per 128-group, m never reset, shift=2*j."""
    d = f16_scale(block['d'])
    kmask1 = 0x03030303
    kmask2 = 0x0f0f0f0f
    a0, a1, a2 = struct.unpack('<III', bytes(block['scales']))
    aux = [0, 0, 0, 0]
    tmp = a2
    aux[2] = ((a0 >> 4) & kmask2) | (((tmp >> 4) & kmask1) << 4)
    aux[3] = ((a1 >> 4) & kmask2) | (((tmp >> 6) & kmask1) << 4)
    aux[0] = (a0 & kmask2) | (((tmp >> 0) & kmask1) << 4)
    aux[1] = (a1 & kmask2) | (((tmp >> 2) & kmask1) << 4)
    scales = np.frombuffer(struct.pack('<IIII', aux[0], aux[1], aux[2], aux[3]),
                           dtype=np.int8).astype(np.int32)

    q = np.frombuffer(bytes(block['qs']), dtype=np.uint8).astype(np.int32)
    hm = np.frombuffer(bytes(block['hmask']), dtype=np.uint8).astype(np.int32)
    is_ = 0
    for n in range(0, QK_K, 128):
        qbase = (n // 128) * 32
        shift = 0
        m = 1 << (4 * (n // 128))
        for j in range(4):
            dl = d * float(scales[is_]); is_ += 1
            for l in range(32):
                w = n + j * 32 + l
                out[base + w] = dl * (float((q[qbase + l] >> shift) & 3) -
                                      (0.0 if (hm[l] & m) else 4.0))
            shift += 2
            m <<= 1

# Simpler: parse GGUF tensor data directly into blocks
def parse_q3_K_blocks(raw_bytes, n_blocks):
    """block_q3_K layout per ggml-common.h: hmask[32], qs[64], scales[12], half d (d LAST)."""
    blocks = []
    off = 0
    for _ in range(n_blocks):
        hmask = raw_bytes[off:off + 32]; off += 32
        qs = raw_bytes[off:off + 64]; off += 64
        scales = raw_bytes[off:off + 12]; off += 12
        d = struct.unpack_from('<H', raw_bytes, off)[0]; off += 2
        blocks.append({'d': d, 'hmask': list(hmask), 'qs': list(qs), 'scales': list(scales)})
    return blocks

def dequant_q3_K_row(blocks, n_elem):
    """Dequantize a full row (multiple blocks) into float64 array."""
    out = np.zeros(n_elem, dtype=np.float64)
    for bi, blk in enumerate(blocks):
        dequant_block_q3_K(blk, out, bi * QK_K)
    return out

def q8K_quantize(x):
    """ggml quantize_row_q8_K_ref equivalent -> (qs int8 array, d array)"""
    n = x.shape[0]
    nb = n // QK_K
    qs = np.zeros(n, dtype=np.int8)
    ds = np.zeros(nb, dtype=np.float64)
    for i in range(nb):
        chunk = x[i * QK_K:(i + 1) * QK_K]
        amax = 0.0; mx = 0.0
        for v in chunk:
            ax = abs(v)
            if ax > amax:
                amax = ax; mx = v
        if amax == 0:
            ds[i] = 0.0
            continue
        iscale = -127.0 / mx
        q = np.zeros(QK_K, dtype=np.int8)
        for j in range(QK_K):
            v = iscale * chunk[j]
            # nearest_int: float trick
            val = v + 12582912.0
            ii = struct.unpack('<i', struct.pack('<f', np.float32(val)))[0]
            r = (ii & 0x007fffff) - 0x00400000
            q[j] = min(127, r)
        qs[i * QK_K:(i + 1) * QK_K] = q
        ds[i] = 1.0 / iscale
    return qs, ds

def f16_scale(u16):
    return float(np.frombuffer(struct.pack('<H', int(u16)), dtype=np.float16)[0])

def dot_q3K_q8K(block, q8, d8):
    """ggml_vec_dot_q3_K_q8_K_generic for one block (exact port)."""
    kmask1 = 0x03030303
    kmask2 = 0x0f0f0f0f
    a0, a1, a2 = struct.unpack('<III', bytes(block['scales']))
    aux = [0, 0, 0, 0]
    tmp = a2
    aux[2] = ((a0 >> 4) & kmask2) | (((tmp >> 4) & kmask1) << 4)
    aux[3] = ((a1 >> 4) & kmask2) | (((tmp >> 6) & kmask1) << 4)
    aux[0] = (a0 & kmask2) | (((tmp >> 0) & kmask1) << 4)
    aux[1] = (a1 & kmask2) | (((tmp >> 2) & kmask1) << 4)
    scales = np.frombuffer(struct.pack('<IIII', aux[0], aux[1], aux[2], aux[3]),
                           dtype=np.int8).astype(np.int32)

    q3 = np.frombuffer(bytes(block['qs']), dtype=np.uint8).astype(np.int32)
    hm = np.frombuffer(bytes(block['hmask']), dtype=np.uint8).astype(np.int32)
    d = f16_scale(block['d']) * d8

    # Build a[] exactly as ggml_vec_dot_q3_K_q8_K_generic:
    #   for n in 0..QK_K step 128:  for j in 0..3: shift=2*j, m=1<<(j+4*(n/128))
    #   weight w = n + j*32 + l ; qs index = (n/128)*32 + l ; hmask index = l
    a = np.zeros(QK_K, dtype=np.int32)
    for n in range(0, QK_K, 128):
        qbase = (n // 128) * 32
        m = 1 << (4 * (n // 128))
        for j in range(4):
            shift = 2 * j
            for l in range(32):
                w = n + j * 32 + l
                qval = (q3[qbase + l] >> shift) & 3
                hbit = 0 if (hm[l] & m) else 4
                a[w] = qval - hbit
            m <<= 1

    aux32 = np.zeros(8, dtype=np.int64)
    qi = 0
    ai = 0
    for j in range(16):
        for l in range(8):
            aux32[l] += (int(scales[j]) - 32) * (int(q8[qi + l]) * int(a[ai + l]))
        qi += 8; ai += 8
        for l in range(8):
            aux32[l] += (int(scales[j]) - 32) * (int(q8[qi + l]) * int(a[ai + l]))
        qi += 8; ai += 8
    sums = np.zeros(8, dtype=np.float64)
    for l in range(8):
        sums[l] += d * float(aux32[l])
    return float(sums.sum())

# ---------------- Run the isolated test ----------------
POS = 10
LAYER = 0
rows, cols = 3072, 8192  # ffn_down: out=3072, in=8192

reader = gguf.GGUFReader(MODEL)
tname = f"blk.{LAYER}.ffn_down.weight"
td = None
for t in reader.tensors:
    if t.name == tname:
        td = t
        break
assert td is not None, tname
raw = td.data.tobytes() if hasattr(td.data, 'tobytes') else bytes(td.data)
n_blocks = cols // QK_K
blocks = parse_q3_K_blocks(raw, n_blocks)
print(f"ffn_down L{POS} L{LAYER}: type={td.tensor_type} rows={rows} cols={cols} blocks/row={n_blocks}")

# input = Deep2's swiglu output (its actual GEMV input) -> isolates GEMV arithmetic
x = d2_tensor(POS, LAYER, 'swiglu')
assert x is not None and x.shape[0] == cols
# reference ffn_out
ref = d2_tensor_ref = None
bp = os.path.join(REF, f"ref_pos{POS}_layer{LAYER}_ffn_out_layer{LAYER}_stage1.bin")
if not os.path.exists(bp):
    bp = os.path.join(REF, f"ref_pos{POS}_layer{LAYER}_ffn_out_layer{LAYER}.bin")
ref = load_bin(bp)
# Deep2 GPU-mode ffn_out
gp = os.path.join(D2, f"d2_pos{POS}_blk{LAYER}")
tr = build_trace(POS)
pc = tr[(LAYER, 'ffn_out')]
d2_out = load_bin(os.path.join(D2, f"d2_pos{POS}_blk{LAYER}_pc{pc}_ffn_out.bin"))

print("\n=== A) F32 dequant x F32 accumulate (GPU-shader style) ===")
# dequantize each row, then dot with x in f32
W = np.zeros((rows, cols), dtype=np.float64)
for r in range(min(rows, 64)):   # test first 64 rows for speed
    W[r] = dequant_q3_K_row(blocks[r * n_blocks:(r + 1) * n_blocks], cols)
A = W[:64] @ x
ref64 = ref[:64]
d264 = d2_out[:64]
print(f"  F32-dequant vs REF : cos={np.dot(A, ref64)/(np.linalg.norm(A)*np.linalg.norm(ref64)):.8f}")
print(f"  F32-dequant vs D2  : cos={np.dot(A, d264)/(np.linalg.norm(A)*np.linalg.norm(d264)):.8f}")

print("\n=== B) Integer dot (Q3_K x Q8_K) ===")
q8, ds = q8K_quantize(x)
B = np.zeros(64, dtype=np.float64)
for r in range(64):
    rowblocks = blocks[r * n_blocks:(r + 1) * n_blocks]
    s = 0.0
    for bi, blk in enumerate(rowblocks):
        s += dot_q3K_q8K(blk, q8[bi * QK_K:(bi + 1) * QK_K], ds[bi])
    B[r] = s
print(f"  int-dot  vs REF    : cos={np.dot(B, ref64)/(np.linalg.norm(B)*np.linalg.norm(ref64)):.8f}")
print(f"  int-dot  vs D2     : cos={np.dot(B, d264)/(np.linalg.norm(B)*np.linalg.norm(d264)):.8f}")

print(f"\n  REF vs D2(gpu-mode): cos={np.dot(ref64, d264)/(np.linalg.norm(ref64)*np.linalg.norm(d264)):.8f}")
print("\nInterpretation: whichever of A/B is closer to REF is the arithmetic llama.cpp used.")
