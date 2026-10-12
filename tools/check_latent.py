import os
import json
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


cert_dir = r'F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1'
dump_dir = r'F:\rawrxd\evidence\RAWRXD_DEEP2_RUNTIME_PARITY_001\dump'

lat = read_cert(os.path.join(cert_dir, 'rec_000003_op0_MLA_kv_latent_l0_p1_kv_latent.bin'))
mla = read_cert(os.path.join(cert_dir, 'rec_000009_op2_MlaDecompress_Output_l0_p1_output.bin'))
krr = read_cert(os.path.join(cert_dir, 'rec_000004_op0_MLA_k_rope_raw_l0_p1_k_rope_raw.bin'))
krp = read_cert(os.path.join(cert_dir, 'rec_000005_op0_MLA_k_rope_l0_p1_k_rope.bin'))
emb = read_cert(os.path.join(cert_dir, 'rec_000000_op0_Linear_Output_l4294967295_p1_output.bin'))

print('ground truth latent   : n=%d L2=%.4f mean|x|=%.6f' % (lat.size, np.linalg.norm(lat), np.abs(lat).mean()))
print('ground truth k_rope_raw: n=%d L2=%.4f first5=%s' % (krr.size, np.linalg.norm(krr), ['%.5f' % x for x in krr[:5]]))
print('ground truth k_rope    : n=%d L2=%.4f first5=%s' % (krp.size, np.linalg.norm(krp), ['%.5f' % x for x in krp[:5]]))
print('ground truth k_rope tail (the rope slice of k):', ['%.5f' % x for x in krp[-8:]])
print()
print('k_rope_raw vs k_rope first 5:', ['%s' % ('MATCH' if abs(krr[i]-krp[i])<1e-4 else 'DIFF') for i in range(5)])
print('  k_raw [0:4]:', ['%.4f' % x for x in krr[:4]])
print('  k_rope[0:4]:', ['%.4f' % x for x in krp[:4]])
print()
print('note: k_rope_raw L2 (%.4f) vs k_rope L2 (%.4f) -> rotation preserves L2, as expected.' % (
    np.linalg.norm(krr), np.linalg.norm(krp)))
print()
# The native k rope region was ~10x too large in magnitude (e.g. -1.83 vs 0.13).
# Check: does ground truth k rope match k_rope_raw (i.e. position 0 -> no rotation)?
d = krr - krp
print('max|k_rope_raw - k_rope| =', float(np.abs(d).max()))
