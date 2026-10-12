import os
import struct
import numpy as np


def read_cert(path):
    """Read a differential capture produced by the certified executor.

    Header is: op_id (u32), layer (u32), position (u64), ndim (u32),
    dims (ndim * i64), count (u64), then count * f32.
    """
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
    return np.array(vals, dtype=np.float32), dims, position


def read_native_dump(path):
    return np.fromfile(path, dtype=np.float32)


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

cert_emb, _, _ = read_cert(os.path.join(cert_dir, 'rec_000000_op0_Linear_Output_l4294967295_p1_output.bin'))
cert_norm, _, _ = read_cert(os.path.join(cert_dir, 'rec_000001_op1_RMSNorm_Output_l0_p1_output.bin'))
cert_q, _, _ = read_cert(os.path.join(cert_dir, 'rec_000010_op3_Linear_Output_l0_p1_output.bin'))

n = cert_emb.size
rms = np.sqrt(float((cert_emb.astype(np.float64) ** 2).sum()) / n + 1e-6)
manual_norm = cert_emb / rms

print('cert embedding   L2=%.6f first5=%s' % (np.linalg.norm(cert_emb), cert_emb[:5]))
print('cert attn_norm   L2=%.6f first5=%s' % (np.linalg.norm(cert_norm), cert_norm[:5]))
print('manual rmsnorm   L2=%.6f first5=%s' % (np.linalg.norm(manual_norm), manual_norm[:5]))
print('cos(manual, cert_norm) = %.8f' % cos(manual_norm, cert_norm))
print('ratio cert_norm[0]/emb[0] = %.6f (manual=%.6f)' % (
    cert_norm[0] / cert_emb[0] if cert_emb[0] else float('nan'), rms))

# The runtime graph's first linear (lin3) is q = attn_norm @ attn_q.
rt_q = read_native_dump(os.path.join(dump_dir, 't_lin3_pos0.bin'))
print()
print('cert q  L2=%.6f' % np.linalg.norm(cert_q))
print('rt   q  L2=%.6f' % np.linalg.norm(rt_q))
print('cos(cert_q, rt_q) = %.8f' % cos(rt_q, cert_q))

# Does the runtime q look like norm(emb) @ attn_q with the CERT norm?
# Solve for the effective scale by regressing rt_q on cert_q.
rt = rt_q.astype(np.float64)
cf = cert_q.astype(np.float64)
denom = float(cf @ cf)
scale = float(rt @ cf / denom) if denom else float('nan')
print()
print('best-fit scale rt_q = %.6f * cert_q' % scale)
print('residual after scale: %.6f' % float(np.linalg.norm(rt - scale * cf) / max(np.linalg.norm(cf), 1e-12)))
