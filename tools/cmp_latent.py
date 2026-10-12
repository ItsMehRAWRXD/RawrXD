import os
import struct
import json
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


def load(path):
    return np.fromfile(path, dtype=np.float32).astype(np.float64)


def cos(a, b):
    a = np.asarray(a, dtype=np.float64).ravel()
    b = np.asarray(b, dtype=np.float64).ravel()
    n = min(a.size, b.size)
    if n == 0:
        return float('nan')
    a, b = a[:n], b[:n]
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    if na == 0 or nb == 0:
        return float('nan')
    return float(a @ b / (na * nb))


cert_dir = r'F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1'
dump_dir = r'F:\rawrxd\evidence\RAWRXD_DEEP2_MLA_DIVERGENCE_003\dump'

# Ground truth: latent 512 and rope 64. Ground truth k_rope_raw IS the
# kv_a_mqa rope tail for this token (pre-rotation).
gt_latent = read_cert(os.path.join(cert_dir, 'rec_000003_op0_MLA_kv_latent_l0_p1_kv_latent.bin'))
gt_rope_raw = read_cert(os.path.join(cert_dir, 'rec_000004_op0_MLA_k_rope_raw_l0_p1_k_rope_raw.bin'))

r_lf = load(os.path.join(dump_dir, 't_latentFull_pos1.bin'))
r_lt = load(os.path.join(dump_dir, 't_latent_pos1.bin'))
r_x = load(os.path.join(dump_dir, 't_mla_x_pos1.bin'))
r_nw = load(os.path.join(dump_dir, 't_nw_pos1.bin'))

print('runtime latentFull: n=%d L2=%.4f' % (r_lf.size, np.linalg.norm(r_lf)))
print('runtime latent    : n=%d L2=%.4f mean|x|=%.6f' % (r_lt.size, np.linalg.norm(r_lt), np.abs(r_lt).mean()))
print('runtime norm w    : n=%d L2=%.4f' % (r_nw.size, np.linalg.norm(r_nw)))
print('runtime x         : n=%d L2=%.4f  (should be attn_norm, L2 27.84)' % (r_x.size, np.linalg.norm(r_x)))
print()
print('ground latent     : n=%d L2=%.4f mean|x|=%.6f' % (gt_latent.size, np.linalg.norm(gt_latent), np.abs(gt_latent).mean()))
print('ground rope_raw   : n=%d L2=%.4f mean|x|=%.6f' % (gt_rope_raw.size, np.linalg.norm(gt_rope_raw), np.abs(gt_rope_raw).mean()))
print()

lora = 512
# Compare the pre-norm latentFull slice to ground truth latent? Ground truth
# 'kv_latent' is the POST-norm value (it is what gets cached). So compare the
# runtime's post-norm `latent` against it.
print('cos(runtime latent, ground latent) = %.8f' % cos(r_lt, gt_latent))
print('cos(runtime latentFull[:512], ground latent) = %.8f' % cos(r_lf[:512], gt_latent))

# And the rope tail: runtime latentFull[512:576] vs ground rope_raw
if r_lf.size >= 576:
    print()
    print('cos(runtime latentFull[512:576], ground rope_raw) = %.8f' % cos(r_lf[512:576], gt_rope_raw))
    print('runtime latFull rope first5:', ['%.5f' % x for x in r_lf[512:517]])
    print('ground  rope_raw  first5:', ['%.5f' % x for x in gt_rope_raw[:5]])

print()
print('runtime latentFull first8:', ['%.5f' % x for x in r_lf[:8]])
print('ground  latent   first8:', ['%.5f' % x for x in gt_latent[:8]])
