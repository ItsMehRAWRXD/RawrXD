import os
import numpy as np


def read_cert(path):
    raw = open(path, 'rb').read()
    off = 0
    op_id, layer = struct_unpack_ii(raw, off); off += 8
    position, = struct_unpack_q(raw, off); off += 8
    ndim, = struct_unpack_i(raw, off); off += 4
    dims = []
    for _ in range(ndim):
        dims.append(struct_unpack_q(raw, off)[0]); off += 8
    count, = struct_unpack_q(raw, off); off += 8
    return np.frombuffer(raw[off:off + count * 4], dtype='<f4').astype(np.float64)


import struct


def struct_unpack_ii(raw, off):
    return struct.unpack_from('<II', raw, off)


def struct_unpack_q(raw, off):
    return struct.unpack_from('<Q', raw, off)


def struct_unpack_i(raw, off):
    return struct.unpack_from('<I', raw, off)


def cos(a, b):
    a = np.asarray(a, dtype=np.float64)
    b = np.asarray(b, dtype=np.float64)
    return float(a @ b / (np.linalg.norm(a) * np.linalg.norm(b)))


q = np.fromfile(r'F:\rawrxd\evidence\RAWRXD_DEEP2_RUNTIME_PARITY_001\dump\t_lin3_pos1.bin',
                dtype=np.float32).astype(np.float64)
g = read_cert(r'F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1\rec_000010_op3_Linear_Output_l0_p1_output.bin')

print('q size=%d g size=%d' % (q.size, g.size))

g16 = g.reshape(16, 192)
q_hd = q.reshape(16, 192)     # q as [head][dim]
q_dh = q.reshape(192, 16).T   # q interpreted as [dim][head]

print('cos(q[head][dim], g)      = %.6f' % cos(q_hd.flatten(), g.flatten()))
print('cos(q[dim][head].T, g)    = %.6f' % cos(q_dh.flatten(), g.flatten()))

print('\ng      first 8: %s' % ['%.4f' % x for x in g[:8]])
print('q      first 8: %s' % ['%.4f' % x for x in q[:8]])

print('\nper-head cos (q as [head][dim]):')
for h in range(6):
    print('  head %2d cos=%.6f rtL2=%9.4f gtL2=%9.4f' %
          (h, cos(q_hd[h], g16[h]), np.linalg.norm(q_hd[h]), np.linalg.norm(g16[h])))

print('\nper-head cos if q were transposed:')
gdh = g.reshape(192, 16).T  # g as [head][dim] from [dim][head]
for h in range(6):
    q_h = q.reshape(192, 16)[:, h]
    print('  head %2d cos=%.6f' % (h, cos(q_h, gdh[h])))
