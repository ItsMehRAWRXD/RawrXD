import os
import numpy as np

D2 = r'F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone'
REF = r'F:\rawrxd\evidence\deep2_gate_a\ref_intermediate_v2'

def lb(p):
    with open(p, 'rb') as f:
        return np.frombuffer(f.read(), dtype='<f4').astype(np.float64)

print('pos  cosine      maxabs     argmax')
coss = []
fails = 0
for pos in range(21):
    d2 = lb(os.path.join(D2, f'd2_logits_pos{pos}.bin'))
    ref = lb(os.path.join(REF, f'ref_logits_pos{pos}.bin'))
    c = np.dot(d2, ref)/(np.linalg.norm(d2)*np.linalg.norm(ref))
    d = np.abs(d2-ref)
    am = 'MATCH' if np.argmax(d2)==np.argmax(ref) else 'MISMATCH'
    coss.append(c)
    if c < 0.999:
        fails += 1
    print(f'{pos:3d}  {c:.8f}  {d.max():.6f}  {am}')
print()
print(f'positions >= 0.999: {21-fails}/21')
print(f'min cosine: {min(coss):.8f} at pos {int(np.argmin(coss))}')
print(f'mean cosine: {np.mean(coss):.8f}')
print(f'milestone (0-4) min: {min(coss[:5]):.8f}')
