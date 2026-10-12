import struct, sys
import numpy as np

# Read token_embd row for token 185 directly from the GGUF (Q4_0) and compare with
# the runtime graph's first Linear (lin3) which is q = attn_norm @ attn_q, and the
# embedding itself which we can compute from the raw rows.
gguf = r'F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf'
f = open(gguf, 'rb')
assert f.read(4) == b'GGUF'
struct.unpack('<I', f.read(4))
tc = struct.unpack('<Q', f.read(8))[0]
kc = struct.unpack('<Q', f.read(8))[0]

def rs():
    n = struct.unpack('<Q', f.read(8))[0]
    return f.read(n).decode('utf8', 'replace')

def rv(t):
    m = {0:('<B',1),1:('<b',1),2:('<H',2),3:('<h',2),4:('<I',4),5:('<i',4),6:('<f',4),7:('<?',1),10:('<Q',8),11:('<q',8),12:('<d',8)}
    if t in m:
        fmt, sz = m[t]
        return struct.unpack(fmt, f.read(sz))[0]
    if t == 8: return rs()
    if t == 9:
        et = struct.unpack('<I', f.read(4))[0]
        c = struct.unpack('<Q', f.read(8))[0]
        return [rv(et) for _ in range(c)]
    raise ValueError()

for _ in range(kc):
    rs(); t = struct.unpack('<I', f.read(4))[0]; rv(t)

tensors = {}
for _ in range(tc):
    n = rs(); nd = struct.unpack('<I', f.read(4))[0]
    d = [struct.unpack('<Q', f.read(8))[0] for _ in range(nd)]
    tt = struct.unpack('<I', f.read(4))[0]
    off = struct.unpack('<Q', f.read(8))[0]
    tensors[n] = (tt, d, off)

data_start = 3996128
tt, d, off = tensors['token_embd.weight']   # [2048, 102400], Q4_0, 32 vals/block
row_bytes = (d[0] // 256) * 210 if tt == 14 else (d[0] // 32) * 18
row_bytes = (2048 // 32) * 18 if tt == 2 else row_bytes
print('token_embd type=%d dims=%s row_bytes=%d' % (tt, d, row_bytes))

def dequant_q4_0(raw):
    # Q4_0: fp16 scale then 16 bytes of nibbles -> 32 values
    out = []
    for b in range(0, len(raw), 18):
        scale = np.frombuffer(raw[b:b+2], dtype='<f2')[0]
        nib = raw[b+2:b+18]
        for i in range(16):
            lo = (nib[i] & 0x0F) - 8
            hi = ((nib[i] >> 4) & 0x0F) - 8
            out.append(float(scale) * lo)
            out.append(float(scale) * hi)
    return np.array(out, dtype=np.float32)

f.seek(data_start + off + 185 * row_bytes)
raw = f.read(row_bytes)
emb185 = dequant_q4_0(raw)
print('embedding[185]: L2=%.6f first6=%s' % (np.linalg.norm(emb185), ['%.5f' % x for x in emb185[:6]]))

# Now the runtime graph dumped lin3 (q = attn_norm @ attn_q) and attn_norm came
# from RmsNorm(embedding). We dumped no rms, so instead validate the embedding by
# checking the reference logits' first position embedding indirectly: the runtime
# graph's logits[0] vs reference logits[0] cosine is the end-to-end check.
dump = r'F:\rawrxd\evidence\RAWRXD_DEEP2_RUNTIME_PARITY_001\dump'
nat0 = np.fromfile(os.path.join(dump, 't_logits_pos0.bin'), dtype=np.float32) if (os := __import__('os')) else None
ref0 = np.fromfile(r'F:\rawrxd\evidence\RAWRXD_REFERENCE_REPRODUCIBILITY_001\ref_teacher_forced\ref_logits_pos0.bin', dtype=np.float32)
cos = float(nat0 @ ref0 / (np.linalg.norm(nat0) * np.linalg.norm(ref0)))
print('\npos0 logits cosine vs llama.cpp: %.6f  argmax native=%d ref=%d' % (cos, int(nat0.argmax()), int(ref0.argmax())))

nat1 = np.fromfile(os.path.join(dump, 't_logits_pos1.bin'), dtype=np.float32)
ref1 = np.fromfile(r'F:\rawrxd\evidence\RAWRXD_REFERENCE_REPRODUCIBILITY_001\ref_teacher_forced\ref_logits_pos1.bin', dtype=np.float32)
cos1 = float(nat1 @ ref1 / (np.linalg.norm(nat1) * np.linalg.norm(ref1)))
print('pos1 logits cosine vs llama.cpp: %.6f  argmax native=%d ref=%d' % (cos1, int(nat1.argmax()), int(ref1.argmax())))
