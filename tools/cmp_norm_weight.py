import os
import struct
import numpy as np


def read_cert(path):
    raw = open(path, 'rb').read()
    off = 0
    op_id, layer = struct.unpack_from('<II', raw, off)
    off += 8
    position, = struct.unpack_from('<Q', raw, off)
    off += 8
    ndim, = struct.unpack_from('<I', raw, off)
    off += 4
    dims = []
    for _ in range(ndim):
        dims.append(struct.unpack_from('<q', raw, off)[0])
        off += 8
    count, = struct.unpack_from('<Q', raw, off)
    off += 8
    vals = struct.unpack_from('<%df' % count, raw, off)
    return np.array(vals, dtype=np.float32)


def read_rawh(path):
    raw = open(path, 'rb').read()
    assert raw[:4] == b'RAWH'
    ne = struct.unpack_from('<4q', raw, 4)
    n = (len(raw) - 68) // 4
    vals = struct.unpack_from('<%df' % n, raw, 68)
    return np.array(vals, dtype=np.float32).reshape(ne)


cert_dir = r'F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1'
stages = r'F:\rawrxd\evidence\RAWRXD_REFERENCE_REPRODUCIBILITY_001\ref_stages'

emb = read_cert(os.path.join(cert_dir, 'rec_000000_op0_Linear_Output_l4294967295_p1_output.bin'))
cert_norm = read_cert(os.path.join(cert_dir, 'rec_000001_op1_RMSNorm_Output_l0_p1_output.bin'))

n = emb.size
print('n =', n)

# If cert_norm = emb / rms_eff * w, then cert_norm / emb = w / rms_eff should vary.
# If cert_norm = emb * c (no weight), cert_norm/emb is constant.
ratio = cert_norm.astype(np.float64) / np.where(emb == 0, np.nan, emb.astype(np.float64))
valid = ratio[np.isfinite(ratio)]
print('cert_norm/emb: min=%.6f max=%.6f mean=%.6f std=%.6f' % (
    valid.min(), valid.max(), valid.mean(), valid.std()))

# Compare with the model's own attn_norm.weight if we can read it (F32).
import struct as _s
gguf = r'F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf'
f = open(gguf, 'rb')
assert f.read(4) == b'GGUF'
_s.unpack('<I', f.read(4))
tc = _s.unpack('<Q', f.read(8))[0]
kc = _s.unpack('<Q', f.read(8))[0]


def rs():
    nn = _s.unpack('<Q', f.read(8))[0]
    return f.read(nn).decode('utf8', 'replace')


def rv(t):
    m = {0: ('<B', 1), 1: ('<b', 1), 2: ('<H', 2), 3: ('<h', 2), 4: ('<I', 4),
         5: ('<i', 4), 6: ('<f', 4), 7: ('<?', 1), 10: ('<Q', 8), 11: ('<q', 8),
         12: ('<d', 8)}
    if t in m:
        fmt, sz = m[t]
        return _s.unpack(fmt, f.read(sz))[0]
    if t == 8:
        return rs()
    if t == 9:
        et = _s.unpack('<I', f.read(4))[0]
        c = _s.unpack('<Q', f.read(8))[0]
        return [rv(et) for _ in range(c)]
    raise ValueError(t)


for _ in range(kc):
    rs(); t = _s.unpack('<I', f.read(4))[0]; rv(t)

tensors = {}
for _ in range(tc):
    nm = rs(); nd = _s.unpack('<I', f.read(4))[0]
    d = [_s.unpack('<Q', f.read(8))[0] for _ in range(nd)]
    tt = _s.unpack('<I', f.read(4))[0]
    off = _s.unpack('<Q', f.read(8))[0]
    tensors[nm] = (tt, d, off)

data_start = 3996128
tt, d, off = tensors['blk.0.attn_norm.weight']
f.seek(data_start + off)
raw = f.read(tt and (2048 * 4 if tt == 0 else 2048))
if tt == 0:
    w = np.frombuffer(raw, dtype='<f4').astype(np.float64)
    print('\nblk.0.attn_norm.weight: n=%d L2=%.4f min=%.4f max=%.4f' % (w.size, np.linalg.norm(w), w.min(), w.max()))
    # implied rms_eff
    implied = w / ratio if False else None
    # cert_norm = emb * w / rms  -> rms = emb*w/cert_norm
    with np.errstate(divide='ignore', invalid='ignore'):
        rms_est = (emb.astype(np.float64) * w) / cert_norm.astype(np.float64)
    rms_est = rms_est[np.isfinite(rms_est)]
    print('implied RMS: min=%.6f max=%.6f mean=%.6f' % (rms_est.min(), rms_est.max(), rms_est.mean()))
    # true rms of emb
    true_rms = np.sqrt(float((emb.astype(np.float64) ** 2).sum()) / n)
    print('true RMS of emb = %.6f' % true_rms)
    print('ratio true/implied = %.6f' % (true_rms / rms_est.mean()))
