import os
import struct
import numpy as np

GGUF = r'F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf'
DATA_START = 3996416


def read_cert(path):
    raw = open(path, 'rb').read()
    off = 0
    off += 8
    _, = struct.unpack_from('<Q', raw, off); off += 8
    ndim, = struct.unpack_from('<I', raw, off); off += 4
    for _ in range(ndim):
        off += 8
    count, = struct.unpack_from('<Q', raw, off); off += 8
    return np.frombuffer(raw[off:off + count * 4], dtype='<f4').astype(np.float64)


def load_dir():
    f = open(GGUF, 'rb')
    assert f.read(4) == b'GGUF'
    struct.unpack('<I', f.read(4))
    tc = struct.unpack('<Q', f.read(8))[0]
    kc = struct.unpack('<Q', f.read(8))[0]

    def rs():
        n = struct.unpack('<Q', f.read(8))[0]
        return f.read(n).decode('utf8', 'replace')

    def rv(t):
        m = {0: ('<B', 1), 1: ('<b', 1), 2: ('<H', 2), 3: ('<h', 2), 4: ('<I', 4),
             5: ('<i', 4), 6: ('<f', 4), 7: ('<?', 1), 10: ('<Q', 8), 11: ('<q', 8),
             12: ('<d', 8)}
        if t in m:
            fmt, sz = m[t]
            return struct.unpack(fmt, f.read(sz))[0]
        if t == 8:
            return rs()
        if t == 9:
            et = struct.unpack('<I', f.read(4))[0]
            c = struct.unpack('<Q', f.read(8))[0]
            return [rv(et) for _ in range(c)]
        raise ValueError(t)

    for _ in range(kc):
        rs(); t = struct.unpack('<I', f.read(4))[0]; rv(t)
    ts = {}
    for _ in range(tc):
        nm = rs(); nd = struct.unpack('<I', f.read(4))[0]
        d = [struct.unpack('<Q', f.read(8))[0] for _ in range(nd)]
        tt = struct.unpack('<I', f.read(4))[0]
        off = struct.unpack('<Q', f.read(8))[0]
        ts[nm] = (tt, d, off)
    f.close()
    return ts


TS = load_dir()
cert_dir = r'F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1'
emb = read_cert(os.path.join(cert_dir, 'rec_000000_op0_Linear_Output_l4294967295_p1_output.bin'))
cert_norm = read_cert(os.path.join(cert_dir, 'rec_000001_op1_RMSNorm_Output_l0_p1_output.bin'))
ground_q = read_cert(os.path.join(cert_dir, 'rec_000010_op3_Linear_Output_l0_p1_output.bin'))
w = np.frombuffer(open(GGUF, 'rb').read()[DATA_START + TS['blk.0.attn_norm.weight'][2]:][:8192], dtype='<f4').astype(np.float64)
rms = np.sqrt(float((emb ** 2).sum()) / 2048 + 1e-6)
my_norm = emb * w / rms

with open(GGUF, 'rb') as f:
    f.seek(DATA_START + TS['blk.0.attn_q.weight'][2])
    raw_q = f.read((2048 * 3072 // 256) * 144)


def dequant_q4k(raw, nvals, variant):
    out = np.zeros(nvals, dtype=np.float32)
    nblk = (nvals + 255) // 256
    for b in range(nblk):
        base = b * 144
        d = np.frombuffer(raw[base:base + 2], dtype='<f2')[0]
        dmin = np.frombuffer(raw[base + 2:base + 4], dtype='<f2')[0]
        sc = np.zeros(8, dtype=np.int32); mn = np.zeros(8, dtype=np.int32)
        for g in range(8):
            if g < 4:
                sc[g] = raw[base + 4 + g] & 63
                mn[g] = raw[base + 4 + g + 4] & 63
            else:
                sc[g] = ((raw[base + 4 + g + 4] & 15) |
                         ((raw[base + 4 + g - 4] >> 6) << 4))
                mn[g] = ((raw[base + 4 + g + 4] >> 4) |
                         ((raw[base + 4 + g] >> 6) << 4))
        qs = raw[base + 16:base + 144]
        base_i = b * 256
        if variant == 'ggml_standard':
            # ggml: for j in [0,256): gi = (j % 64) // 32 + (j // 64) * 4? No.
            # The canonical ggml order: 8 groups of 32. index = j; low/high nibbles.
            for j in range(128):
                v = qs[j]
                lo = v & 0xF
                hi = (v >> 4) & 0xF
                gi_lo = (j // 32) % 8
                gi_hi = gi_lo + 0
                out[base_i + j] = (d * sc[gi_lo] - dmin * mn[gi_lo]) * lo
                out[base_i + 128 + j] = (d * sc[gi_hi] - dmin * mn[gi_hi]) * hi
        elif variant == 'interleave':
            # alternate lo/hi per byte, group index by 32-block of the output index
            for j in range(128):
                v = qs[j]
                lo = v & 0xF
                hi = (v >> 4) & 0xF
                gi_lo = (j // 64) * 2
                gi_hi = (j // 64) * 2 + 1
                out[base_i + j] = (d * sc[gi_lo] - dmin * mn[gi_lo]) * lo
                out[base_i + 128 + j] = (d * sc[gi_hi] - dmin * mn[gi_hi]) * hi
    return out


# Try both variants and both matrix orientations
for variant in ['ggml_standard', 'interleave']:
    wq = dequant_q4k(raw_q, 2048 * 3072, variant)
    for tag, mat in [('C-order [n_in][n_out]', wq.reshape(2048, 3072)),
                     ('T-order [n_out][n_in]', wq.reshape(3072, 2048).T)]:
        qq = my_norm @ mat
        c = float(qq @ ground_q / (np.linalg.norm(qq) * np.linalg.norm(ground_q)))
        print('%-14s %-22s cos=%.8f' % (variant, tag, c))
