import struct, os
import numpy as np

def read_cert(path):
    raw = open(path,'rb').read()
    off = 0
    op_id, layer = struct.unpack_from('<II', raw, off); off += 8
    position, = struct.unpack_from('<Q', raw, off); off += 8
    ndim, = struct.unpack_from('<I', raw, off);0
    dims = []
    for _ in range(ndim):
        dims.append(struct.unpack_from('<q', raw, off)[0]); off += 8
    count, = struct.unpack_from('<Q', raw, off); off += 8
    vals = struct.unpack_from('<%df' % count, raw, off)
    return np.array(vals, dtype=np.float32)

def read_rawh(path):
    raw = open(path,'rb').read()
    assert raw[:4] == b'RAWH'
    ne = struct.unpack_from('<4q', raw, 4)
    n = (len(raw) - 68)//4
    vals = struct.unpack_from('<%df' % n, raw, 68)
    return np.array(vals, dtype=np.float32).reshape(ne)

cert_dir = r'F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1'

cert_emb = read_cert(os.path.join(cert_dir, 'rec_000000_op0_Linear_Output_l4294967295_p1_output.bin'))
cert_norm = read_cert(os.path.join(cert_dir, 'rec_000001_op1_RMSNorm_Output_l0_p1_output.bin'))

# recompute RMSNorm from the embedding
n = cert_emb.size
ss = float((cert_emb.astype(np.float64)**2).sum())
rms = np.sqrt(ss/n + 1e-6)
manual = cert_emb / rms

print('manual norm L2=%.4f first5=%s' % (np.linalg.norm(manual), manual[:5]))
print('cert   norm L2=%.4f first5=%s' % (np.linalg.norm(cert_norm), cert_norm[:5]))
d = manual - cert_norm.astype(np.float64)
print('ratio manual/cert[0] = %.4f' % (manual[0]/cert_norm[0]))
print('cos = %.8f' % float(manual @ cert_norm / (np.linalg.norm(manual)*np.linalg.norm(cert_norm))))