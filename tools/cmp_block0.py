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

ground = {
    'kv_latent': read_cert(os.path.join(cert_dir, 'rec_000003_op0_MLA_kv_latent_l0_p1_kv_latent.bin')),
    'k_rope_raw': read_cert(os.path.join(cert_dir, 'rec_000004_op0_MLA_k_rope_raw_l0_p1_k_rope_raw.bin')),
    'k_rope': read_cert(os.path.join(cert_dir, 'rec_000005_op0_MLA_k_rope_l0_p1_k_rope.bin')),
    'mla_out': read_cert(os.path.join(cert_dir, 'rec_000009_op2_MlaDecompress_Output_l0_p1_output.bin')),
    'q': read_cert(os.path.join(cert_dir, 'rec_000010_op3_Linear_Output_l0_p1_output.bin')),
    'q_rope': read_cert(os.path.join(cert_dir, 'rec_000011_op4_Attention_Q_RoPE_l0_p1_q_rope.bin')),
    'attn_out': read_cert(os.path.join(cert_dir, 'rec_000016_op4_MLA_PRE_WO_l0_p1_pre_wo.bin')) if os.path.exists(
        os.path.join(cert_dir, 'rec_000016_op4_MLA_PRE_WO_l0_p1_pre_wo.bin')) else None,
}

print('ground truth sizes:')
for k, v in ground.items():
    if v is not None:
        print('  %-12s n=%6d L2=%10.4f' % (k, v.size, np.linalg.norm(v)))

print()
# runtime dumps at position 1 (the certified capture is a 2-token run, index 1)
rt = {}
for f in sorted(os.listdir(dump_dir)):
    p = os.path.join(dump_dir, f)
    rt[f] = np.fromfile(p, dtype=np.float32).astype(np.float64)

for f in sorted(rt):
    if '_pos1' in f:
        v = rt[f]
        print('%-24s n=%6d L2=%10.4f' % (f, v.size, np.linalg.norm(v)))

print()
# Compare MLA outputs (both position 1)
keys = [f for f in rt if '_pos1' in f and f.startswith('t_mla')]
for f in sorted(keys):
    v = rt[f]
    if f.startswith('t_mla_k'):
        ref = ground['mla_out']
    else:
        ref = ground['mla_out']
    # mla_out is [k_nope(5120=16*320?)] actually 5120 total
    print('%s vs ground mla_out: cos=%.6f' % (f, cos(v, ref)))

print()
print('t_lin3_pos1 (q) vs ground q: cos=%.6f' % cos(rt['t_lin3_pos1.bin'], ground['q']))
print('t_attn_pos1 vs ground pre_wo: cos=%.6f' % cos(rt['t_attn_pos1.bin'], ground['attn_out']))
