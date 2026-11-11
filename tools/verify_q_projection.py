import os
import struct
import numpy as np

GGUF = r'F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf'
DATA_START = 3996128


def read_cert(path):
    raw = open(path, 'rb').read()
    off = 0
    off += 8                 # op_id, layer
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


def load_f32(name, n):
    tt, d, off = TS[name]
    with open(GGUF, 'rb') as f:
        f.seek(DATA_START + off)
        raw = f.read(n * 4)
    return np.frombuffer(raw, dtype='<f4').astype(np.float64)


cert_dir = r'F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1'
emb = read_cert(os.path.join(cert_dir, 'rec_000000_op0_Linear_Output_l4294967295_p1_output.bin'))
cert_norm = read_cert(os.path.join(cert_dir, 'rec_000001_op1_RMSNorm_Output_l0_p1_output.bin'))
ground_q = read_cert(os.path.join(cert_dir, 'rec_000010_op3_Linear_Output_l0_p1_output.bin'))

w = load_f32('blk.0.attn_norm.weight', 2048)
n = 2048
rms = np.sqrt(float((emb ** 2).sum()) / n + 1e-6)
norm_out = (emb * w / rms).astype(np.float64)

print('cos(my norm, cert norm) = %.8f' % float(
    norm_out @ cert_norm / (np.linalg.norm(norm_out) * np.linalg.norm(cert_norm))))

# attn_q.weight is Q4_0 [2048, 3072]; dequantise in C order
tt, d, off = TS['blk.0.attn_q.weight']
print('attn_q: tt=%d dims=%s' % (tt, d))


def dequant_q4_0(raw, nvals):
    out = np.zeros(nvals, dtype=np.float64)
    blocks = (nvals + 31) // 32
    for b in range(blocks):
        base = b * 18
        if base + 2 > len(raw):
            break
        scale = np.frombuffer(raw[base:base + 2], dtype='<f2')[0]
        nib = raw[base + 2:base + 18]
        for i in range(16):
            idx = b * 32 + i * 2
            if idx + 1 < nvals:
                out[idx] = scale * ((nib[i] & 0x0F) - 8)
                out[idx + 1] = scale * (((nib[i] >> 4) & 0x0F) - 8)
    return out


with open(GGUF, 'rb') as f:
    f.seek(DATA_START + off)
    raw = f.read(2048 * 3072 // 32 * 18)

# C order [n_in][n_out] = [2048][3072] is what a row-major [2048,3072] holds
wc = dequant_q4_0(raw, 2048 * 3072).reshape(2048, 3072)   # [n_in][n_out]
wt = wc.T                                                  # [n_out][n_in]

q_rowmajor = (norm_out @ wc)          # y[j] = sum_i x[i]*w[i][j]
q_colmajor = (wt @ norm_out)          # y[j] = sum_i w[j][i]*x[i]

for tag, qq in [('x@W  ([n_in][n_out])', q_rowmajor), ('W.T@x ([n_out][n_in])', q_colmajor)]:
    c = float(qq @ ground_q / (np.linalg.norm(qq) * np.linalg.norm(ground_q)))
    s = float(qq @ ground_q / float(ground_q @ ground_q))
    print('%-24s cos=%.8f  scale=%.6f' % (tag, c, s))
