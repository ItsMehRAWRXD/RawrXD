import struct, os
import numpy as np

def read_cert(path):
    raw = open(path,'rb').read()
    off = 0
    op_id, layer = struct.unpack_from('<II', raw, off); off += 8
    position, = struct.unpack_from('<Q', raw, off); off += 8
    ndim, = struct.unpack_from('<I', raw, off); off += 8 if False else 4
    dims = []
    for _ in range(ndim):
        dims.append(struct.unpack_from('<q', raw, off)[0]); off += 8
    count, = struct.unpack_from('<Q', raw, off); off += 8
    vals = struct.unpack_from('<%df' % count, raw, off)
    return np.array(vals, dtype=np.float32), dims, position

def read_dump(path):
    return np.fromfile(path, dtype=np.float32)

cert_dir = r'F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1'
dump_dir = r'F:\rawrxd\evidence\RAWRXD_DEEP2_RUNTIME_PARITY_001\dump'

def cos(a, b):
    n = min(a.size, b.size)
    a = a[:n].astype(np.float64); b = b[:n].astype(np.float64)
    return float(a @ b / (np.linalg.norm(a)*np.linalg.norm(b)))

# certified executor captured op1 RMSNorm_Output (after attn norm) at layer 0
cert_norm, dims, pos = read_cert(os.path.join(cert_dir, 'rec_000001_op1_RMSNorm_Output_l0_p1_output.bin'))
print('cert attn_norm (l0): n=%d L2=%.4f first5=%s' % (cert_norm.size, np.linalg.norm(cert_norm), cert_norm[:5]))

# certified executor captured op0 Linear_Output = embedding
cert_emb, _, _ = read_cert(os.path.join(cert_dir, 'rec_000000_op0_Linear_Output_l4294967295_p1_output.bin'))
print('cert embedding: n=%d L2=%.4f first5=%s' % (cert_emb.size, np.linalg.norm(cert_emb), cert_emb[:5]))

# runtime graph did not dump the norm, but dumped lin3 = q. The certified op3 Linear_Output is q.
cert_q, _, _ = read_cert(os.path.join(cert_dir, 'rec_000010_op3_Linear_Output_l0_p1_output.bin'))
rt_q = read_dump(os.path.join(dump_dir, 't_lin3_pos0.bin'))
print()
print('q: cert n=%d L2=%.4f | runtime n=%d L2=%.4f | cos=%.6f' % (
    cert_q.size, np.linalg.norm(cert_q), rt_q.size, np.linalg.norm(rt_q), cos(rt_q, cert_q)))

# V reconstructed (per-head at position 0): cert rec_000013 (head 0)
cert_v0, _, _ = read_cert(os.path.join(cert_dir, 'rec_000013_op4_MLA_V_RECONSTRUCTED_l0_p1_v_reconstructed.bin'))
print('cert V[head0] n=%d L2=%.4f first5=%s' % (cert_v0.size, np.linalg.norm(cert_v0), cert_v0[:5]))

# kv_latent
cert_kvl, _, _ = read_cert(os.path.join(cert_dir, 'rec_000003_op0_MLA_kv_latent_l0_p1_kv_latent.bin'))
print('cert kv_latent n=%d L2=%.4f first5=%s' % (cert_kvl.size, np.linalg.norm(cert_kvl), cert_kvl[:5]))