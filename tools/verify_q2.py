import os
import struct
import numpy as np

GGUF = r'F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf'
DATA_START = 3996416


def read_cert(path):
    raw = open(path, 'rb').read()
    off = 0
    off += 8
    pos, = struct.unpack_from('<Q', raw, off); off += 8
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
print('attn_q type =', TS['blk.0.attn_q.weight'][0], 'dims =', TS['blk.0.attn_q.weight'][1])
print('attn_norm type =', TS['blk.0.attn_norm.weight'][0])


def load_f32(name, n):
    tt, d, off = TS[name]
    with open(GGUF, 'rb') as f:
        f.seek(DATA_START + off)
        raw = f.read(n * 4)
    return np.frombuffer(raw, dtype='<f4').astype(np.float64)


def dequant_q4_k(raw, nvals):
    """ggml Q4_K super-block: 144 bytes per 256 values."""
    out = np.zeros(nvals, dtype=np.float32)
    nblk = (nvals + 255) // 256
    for b in range(nblk):
        base = b * 144
        if base + 12 > len(raw):
            break
        # fp16 scale/min
        d = np.frombuffer(raw[base:base + 2], dtype='<f2')[0]
        dmin = np.frombuffer(raw[base + 2:base + 4], dtype='<f2')[0]
        # 12 bytes of 6-bit scales/min
        sc = np.zeros(8, dtype=np.int32)
        mn = np.zeros(8, dtype=np.int32)
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
        for j in range(256):
            gi = (j // 32) % 8
            lo = (j % 32)
            byte_idx = lo // 2
            val = qs[lo // 2] if lo % 2 == 0 else (qs[lo // 2] >> 4) & 0xF
            out[base_i + j] = (d * sc[gi] - dmin * mn[gi]) * (val & 0xF)
    return out


def load_q4k(name, nvals):
    tt, d, off = TS[name]
    nbytes = (nvals // 256) * 144
    with open(GGUF, 'rb') as f:
        f.seek(DATA_START + off)
        raw = f.read(nbytes)
    return dequant_q4_k(raw, nvals)


cert_dir = r'F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1'
emb = read_cert(os.path.join(cert_dir, 'rec_000000_op0_Linear_Output_l4294967295_p1_output.bin'))
cert_norm = read_cert(os.path.join(cert_dir, 'rec_000001_op1_RMSNorm_Output_l0_p1_output.bin'))
ground_q = read_cert(os.path.join(cert_dir, 'rec_000010_op3_Linear_Output_l0_p1_output.bin'))

w = load_f32('blk.0.attn_norm.weight', 2048)
rms = np.sqrt(float((emb ** 2).sum()) / 2048 + 1e-6)
my_norm = emb * w / rms
c = float(my_norm @ cert_norm / (np.linalg.norm(my_norm) * np.linalg.norm(cert_norm)))
print('\ncos(my attn_norm, certified) = %.8f' % c)
print('L2 mine=%.4f certified=%.4f' % (np.linalg.norm(my_norm), np.linalg.norm(cert_norm)))

wq = load_q4k('blk.0.attn_q.weight', 2048 * 3072)
print('\nattn_q dequant: n=%d nonfinite=%d first5=%s' %
      (wq.size, int((~np.isfinite(wq)).sum()), wq[:5]))

qr = (my_norm @ wq.reshape(2048, 3072)).astype(np.float64)
cc = float(qr @ ground_q / (np.linalg.norm(qr) * np.linalg.norm(ground_q)))
print('cos(my q, ground q) with [n_in][n_out] = %.8f' % cc)

wq2 = wq.reshape(3072, 2048).T   # [n_in][n_out]
qr2 = (my_norm @ wq2).astype(np.float64)
cc2 = float(qr2 @ ground_q / (np.linalg.norm(qr2) * np.linalg.norm(ground_q)))
print('cos(my q, ground q) with [n_out][n_in].T = %.8f' % cc2)
