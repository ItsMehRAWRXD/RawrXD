import os
import struct
import numpy as np


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


def cos(a, b):
    a = np.asarray(a, dtype=np.float64).ravel()
    b = np.asarray(b, dtype=np.float64).ravel()
    n = min(a.size, b.size)
    if n == 0:
        return float('nan')
    a = a[:n]; b = b[:n]
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    if na == 0 or nb == 0:
        return float('nan')
    return float(a @ b / (na * nb))


cert_dir = r'F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1'
dump_dir = r'F:\rawrxd\evidence\RAWRXD_DEEP2_RUNTIME_PARITY_001\dump'

mla_gt = read_cert(os.path.join(cert_dir, 'rec_000009_op2_MlaDecompress_Output_l0_p1_output.bin'))
k = np.fromfile(os.path.join(dump_dir, 't_mla_k4_pos1.bin'), dtype=np.float32).astype(np.float64)
v = np.fromfile(os.path.join(dump_dir, 't_mla_v4_pos1.bin'), dtype=np.float32).astype(np.float64)

print('ground truth mla_out: n=%d' % mla_gt.size)
print('native k: n=%d, v: n=%d' % (k.size, v.size))

kv = np.concatenate([k, v])
print('\n(k||v) vs ground truth: cos = %.8f' % cos(kv, mla_gt))

# Try the interleave the ggml reference uses: per head [k_nope(64), v(128), rope(64)]?
# ground truth 5120 = 16 heads * 320.  320 = 192 (nope128+rope64) + 128 (v).
# Try per-head blocks of 320 laid out as [k(192) | v(128)].
per_head = 320
gt2 = mla_gt.reshape(16, per_head)
k2 = k.reshape(16, 192)
v2 = v.reshape(16, 128)
nat2 = np.concatenate([k2, v2], axis=1)  # (16, 320) with k|v layout
print('per-head [k|v] vs ground: cos = %.8f' % cos(nat2, gt2))

# Try [nope(128), rope(64), v(128)] using per-head k as [nope|rope]
kresh = k.reshape(16, 192)
knope, krope = kresh[:, :128], kresh[:, 128:]
nat3 = np.concatenate([knope, krope, v2], axis=1)
print('per-head [nope|rope|v]: cos = %.8f' % cos(nat3, gt2))

print('\nground truth per-head[0,0:8]:', ['%.5f' % x for x in gt2[0, :8]])
print('native k head0[0:8]        :', ['%.5f' % x for x in k2[0, :8]])
print('ground truth per-head[0,192:200] (rope region):', ['%.5f' % x for x in gt2[0, 192:200]])
print('native k head0[128:136] (rope region)        :', ['%.5f' % x for x in k2[0, 128:136]])
