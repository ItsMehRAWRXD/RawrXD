import os
import json
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
    return np.frombuffer(raw[off:off + count * 4], dtype='<f4').astype(np.float6) if False else \
           np.frombuffer(raw[off:off + count * 4], dtype='<f4').astype(np.float64)


def     cos(a, b):
    n = min(a.size, b.size)
    a = np.asarray(a[:n], dtype=np.float64)
    b = np.asarray(b[:n], dtype=np.float64)
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    if na == 0 or nb == 0:
        return float('nan')
    return float(a @ b / (na * nb))


cert_dir = r'F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1'

# ground truth tensors for block 0 position 1
kv_latent = read_cert(os.path.join(cert_dir, 'rec_000003_op0_MLA_kv_latent_l0_p1_kv_latent.bin'))
k_rope_raw = read_cert(os.path.join(cert_dir, 'rec_000004_op0_MLA_k_rope_raw_l0_p1_k_rope_raw.bin'))
k_rope = read_cert(os.path.join(cert_dir, 'rec_000005_op0_MLA_k_rope_l0_p1_k_rope.bin'))
expanded = read_cert(os.path.join(cert_dir, 'rec_000006_op0_MLA_expanded_l0_p1_expanded_KV.bin'))
mla_out = read_cert(os.path.join(cert_dir, 'rec_000009_op2_MlaDecompress_Output_l0_p1_output.bin'))
q = read_cert(os.path.join(cert_dir, 'rec_000010_op3_Linear_Output_l0_p1_output.bin'))
q_rope = read_cert(os.path.join(cert_dir, 'rec_000011_op4_Attention_Q_RoPE_l0_p1_q_rope.bin'))
emb = read_cert(os.path.join(cert_dir, 'rec_000000_op0_Linear_Output_l4294967295_p1_output.bin'))

for nm, t in [('emb', emb), ('kv_latent', kv_latent), ('k_rope_raw', k_rope_raw),
              ('k_rope', k_rope), ('mla_out', mla_out), ('q', q), ('q_rope', q_rope)]:
    print('%-12s n=%5d L2=%10.6f  first5=%s' % (nm, t.size, np.linalg.norm(t),
                                                ['%.5f' % x for x in t[:5]]))
print()
print('expanded n=%d L2=%.6f' % (expanded.size, np.linalg.norm(expanded)))
print('cos(q, q_rope) = %.8f  (should be high: rope only rotates a slice)' % cos(q, q_rope))
print('cos(emb, kv_latent[:2048]) = %.8f' % cos(emb, kv_latent[:2048]))
