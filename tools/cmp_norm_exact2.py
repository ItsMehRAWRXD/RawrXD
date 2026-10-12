import os
import struct
import numpy as np

GGUF = r'F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf'
DATA_START = 3996128


def read_cert(path):
    raw = open(path, 'rb').read()
    off = 0
    op_id, layer = struct.unpack_from('<II', raw, off); off += 8
    position, = struct.unpack_from('<Q', raw, off); off += 8
    ndim, = struct.unpack_from('<I', raw, off); off += 4
    for _ in range(ndim):
        off += 8
    count, = struct.unpack_from('<Q', raw, off); off += 8
    return np.frombuffer(raw[off:off + count * 4], dtype='<f4').astype(np.float64)


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


def load_f32(name):
    tt, d, off = ts[name]
    with open(GGUF, 'rb') as f:
        f.seek(DATA_START + off)
        raw = f.read(2048 * 4)
    return np.frombuffer(raw, dtype='<f4').astype(np.float64)


cert_dir = r'F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1'
emb = read_cert(os.path.join(cert_dir, 'rec_000000_op0_Linear_Output_l4294967295_p1_output.bin'))
cert_norm = read_cert(os.path.join(cert_dir, 'rec_000001_op1_RMSNorm_Output_l0_p1_output.bin'))
w = load_f32('blk.0.attn_norm.weight')
n = 2048
eps = 1e-6

rms = np.sqrt(float((emb ** 2).sum()) / n + eps)
manual = (emb * w / rms).astype(np.float64)
print('mount  L2=%.6f first5=%s' % (np.linalg.norm(manual), manual[:5]))
print('cert   L2=%.6f first5=%s' % (np.linalg.norm(cert_norm), cert_norm[:5]))
c = float(manual @ cert_norm / (np.linalg.norm(manual) * np.linalg.norm(cert_norm)))
print('cos = %.10f' % c)
s = float(manual @ cert_norm / float(manual @ manual))
print('cert_norm = %.8f * manual' % s)
