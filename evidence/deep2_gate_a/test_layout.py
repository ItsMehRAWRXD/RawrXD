import struct, os
import numpy as np
import gguf

MODEL = r'F:\rawrxd\llama3.2-3b-Q2_K.gguf'
QK_K = 256

reader = gguf.GGUFReader(MODEL)
for t in reader.tensors:
    if t.name == 'blk.0.ffn_down.weight':
        td = t
        break
b = bytes(td.data)

def f16s(u):
    return float(np.frombuffer(struct.pack('<H', int(u)), dtype=np.float16)[0])

kmask1 = 0x03030303
kmask2 = 0x0f0f0f0f

def unpack_scales(sc12):
    a0, a1, a2 = struct.unpack('<III', bytes(sc12))
    aux = [0, 0, 0, 0]
    tmp = a2
    aux[2] = ((a0 >> 4) & kmask2) | (((tmp >> 4) & kmask1) << 4)
    aux[3] = ((a1 >> 4) & kmask2) | (((tmp >> 6) & kmask1) << 4)
    aux[0] = (a0 & kmask2) | (((tmp >> 0) & kmask1) << 4)
    aux[1] = (a1 & kmask2) | (((tmp >> 2) & kmask1) << 4)
    return np.frombuffer(struct.pack('<IIII', *aux), dtype=np.int8).astype(np.int32)

def block_at(bi):
    o = bi * 110
    hmask = np.frombuffer(b[o:o + 32], dtype=np.uint8).astype(np.int32)
    qs = np.frombuffer(b[o + 32:o + 96], dtype=np.uint8).astype(np.int32)
    scales = unpack_scales(b[o + 96:o + 108])
    d = f16s(struct.unpack_from('<H', b, o + 108)[0])
    return hmask, qs, scales, d

def dequant_orderA(hmask, qs, scales, d):
    """Reference dot order: a[n + jsub*32 + l], qbase=(n/128)*32, m=1<<(jsub+4*(n/128))"""
    out = np.zeros(QK_K)
    is_ = 0
    for n in range(0, QK_K, 128):
        qbase = (n // 128) * 32
        m = 1 << (4 * (n // 128))
        for jsub in range(4):
            shift = 2 * jsub
            dl = d * float(scales[is_]); is_ += 1
            for l in range(32):
                w = n + jsub * 32 + l
                out[w] = dl * (float((qs[qbase + l] >> shift) & 3) -
                               (0.0 if (hmask[l] & m) else 4.0))
            m <<= 1
    return out

def dequant_orderB(hmask, qs, scales, d):
    """Alternative: scale order from dequantize_row (is++ per group, same as A) but
    treating a[] index as sequential n*... with m never advancing across group"""
    out = np.zeros(QK_K)
    is_ = 0
    m = 1
    for n in range(0, QK_K, 128):
        qbase = (n // 128) * 32
        for jsub in range(4):
            shift = 2 * jsub
            dl = d * float(scales[is_]); is_ += 1
            for l in range(32):
                w = n + jsub * 32 + l
                out[w] = dl * (float((qs[qbase + l] >> shift) & 3) -
                               (0.0 if (hmask[l] & m) else 4.0))
            m <<= 1
    return out

# dequantize_row_q3_K exact reference
def dequant_ref_block(hmask, qs, scales, d):
    out = np.zeros(QK_K)
    is_ = 0
    m = 1
    q3 = qs
    for n in range(0, QK_K, 128):
        shift = 0
        for j in range(4):
            dl = d * float(scales[is_]); is_ += 1
            for l in range(16):
                out[n + j * 32 + l] = dl * (float((q3[l] >> shift) & 3) -
                                            (0.0 if (hmask[l] & m) else 4.0))
            dl = d * float(scales[is_]); is_ += 1
            for l in range(16):
                out[n + j * 32 + 16 + l] = dl * (float((q3[16 + l] >> shift) & 3) -
                                                 (0.0 if (hmask[16 + l] & m) else 4.0))
            shift += 2
            m <<= 1
        q3 = np.concatenate([q3[32:], np.zeros(0, dtype=q3.dtype)])
    return out

# load inputs
D2 = r'F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone'
tr = {}
with open(os.path.join(D2, 'd2_trace_pos10.txt')) as f:
    for line in f:
        if line.startswith('blk='):
            q = line.strip().split()
            tr[(int(q[0].split('=')[1]), q[3].split('=')[1])] = int(q[1].split('=')[1])
sw = tr[(0, 'swiglu')]
x = np.frombuffer(open(os.path.join(D2, f'd2_pos10_blk0_pc{sw}_swiglu.bin'), 'rb').read(),
                  dtype='<f4').astype(np.float64)
fo = tr[(0, 'ffn_out')]
d2out = np.frombuffer(open(os.path.join(D2, f'd2_pos10_blk0_pc{fo}_ffn_out.bin'), 'rb').read(),
                      dtype='<f4').astype(np.float64)

# Build a full dequantized row for orderA and orderB for row 0
for label, fn in [('orderA', dequant_orderA), ('orderB', dequant_orderB)]:
    W = np.zeros((256, 8192))
    for cblk in range(32):
        hm, q, sc, d = block_at(0 * 32 + cblk)
        W[:, cblk * 256:(cblk + 1) * 256] = fn(hm, q, sc, d)
    y = W @ x
    print(f'{label}: row0 vs D2 = {y[0]:.6f}  (D2={d2out[0]:.6f})')
    print(f'   cos(row) = {np.dot(y, d2out[:256])/(np.linalg.norm(y)*np.linalg.norm(d2out[:256])):.6f}')
