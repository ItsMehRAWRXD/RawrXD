import os
import struct
import numpy as np


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


def read_dump(path):
    return np.fromfile(path, dtype=np.float32).astype(np.float64)


def cos(a, b):
    n = min(a.size, b.size)
    a = np.asarray(a[:n], dtype=np.float64)
    b = np.asarray(b[:n], dtype=np.float64)
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    if na == 0 or nb == 0:
        return float('nan')
    return float(a @ b / (na * nb))


cert_dir = r'F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1'
dump_dir = r'F:\rawrxd\evidence\RAWRXD_DEEP2_RUNTIME_PARITY_001\dump'

# Ground truth for position 1 (the certified capture is a 2-token run, so pos index 1)
ground_q = read_cert(os.path.join(cert_dir, 'rec_000010_op3_Linear_Output_l0_p1_output.bin'))
ground_q_rope = read_cert(os.path.join(cert_dir, 'rec_000011_op4_Attention_Q_RoPE_l0_p1_q_rope.bin'))

# The runtime graph ran 3 tokens and dumped per position. pos1 = second position.
rt_q = read_dump(os.path.join(dump_dir, 't_lin3_pos1.bin'))

print('ground q      L2=%.6f' % np.linalg.norm(ground_q))
print('runtime q    L2=%.6f' % np.linalg.norm(rt_q))
print('cos = %.8f' % cos(rt_q, ground_q))

denom = float(ground_q @ ground_q)
s = float(rt_q @ ground_q / denom)
print('best fit runtime_q = %.6f * ground_q' % s)
print('relative residual after scaling = %.8f' %
      float(np.linalg.norm(rt_q - s * ground_q) / np.linalg.norm(ground_q)))

# Is it a pure per-element scale (a missing norm weight) or a rotation/perm?
ratio = rt_q / np.where(ground_q == 0, np.nan, ground_q)
valid = ratio[np.isfinite(ratio)]
print('\nper-element ratio rt/ground: mean=%.6f std=%.6f min=%.6f max=%.6f' %
      (valid.mean(), valid.std(), valid.min(), valid.max()))

# Compare head-block structure: 16 heads of 192
gt16 = ground_q.reshape(16, 192)
rt16 = rt_q.reshape(16, 192)
print('\nper-head cos:')
for h in range(4):
    print('  head %2d cos=%.6f  rtL2=%10.4f gtL2=%10.4f' %
          (h, cos(rt16[h], gt16[h]), np.linalg.norm(rt16[h]), np.linalg.norm(gt16[h])))
