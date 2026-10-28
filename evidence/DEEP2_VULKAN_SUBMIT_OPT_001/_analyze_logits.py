import struct, math, os
evid = r'G:\~dev\rawrxd\evidence\DEEP2_VULKAN_SUBMIT_OPT_001'
path_a = os.path.join(evid, 'logits_force_A', 'd2_logits_pos11.bin')
path_b = os.path.join(evid, 'logits_force_B', 'd2_logits_pos11.bin')

def load(p):
    with open(p,'rb') as f:
        raw = f.read()
    n = len(raw)//4
    return list(struct.unpack('<%df'%n, raw))

def topk(lg, k=10):
    idx = sorted(range(len(lg)), key=lambda i: lg[i], reverse=True)[:k]
    return [(i, lg[i]) for i in idx]

A = load(path_a)
B = load(path_b)
assert len(A)==len(B)
N = len(A)
# errors
max_abs = 0.0; max_rel = 0.0; max_abs_i = 0; max_rel_i = 0
sum_abs = 0.0
for i in range(N):
    d = abs(A[i]-B[i])
    sum_abs += d
    den = max(1e-12, abs(A[i]))
    r = d/den
    if d > max_abs: max_abs, max_abs_i = d, i
    if r > max_rel: max_rel, max_rel_i = r, i
mean_abs = sum_abs/N
ta = topk(A, 10)
tb = topk(B, 10)
a1,a2 = ta[0], ta[1]
b1,b2 = tb[0], tb[1]
ids = (2649, 3867)
print('VOCAB', N)
print('A_TOP1', a1[0], a1[1], 'A_TOP2', a2[0], a2[1], 'A_MARGIN', a1[1]-a2[1])
print('B_TOP1', b1[0], b1[1], 'B_TOP2', b2[0], b2[1], 'B_MARGIN', b1[1]-b2[1])
print('MAX_ABS', max_abs, 'AT', max_abs_i, 'A', A[max_abs_i], 'B', B[max_abs_i])
print('MAX_REL', max_rel, 'AT', max_rel_i)
print('MEAN_ABS', mean_abs)
print('LOGIT_2649_A', A[2649], 'B', B[2649], 'DIFF', A[2649]-B[2649])
print('LOGIT_3867_A', A[3867], 'B', B[3867], 'DIFF', A[3867]-B[3867])
print('A_TOP10', ' '.join('%d:%.6g'%x for x in ta))
print('B_TOP10', ' '.join('%d:%.6g'%x for x in tb))
# rank of 2649/3867 in each
def rank_of(lg, tid):
    v = lg[tid]
    return 1 + sum(1 for x in lg if x > v)
print('RANK_2649_A', rank_of(A,2649), 'B', rank_of(B,2649))
print('RANK_3867_A', rank_of(A,3867), 'B', rank_of(B,3867))
# also compare pos10 (after gen[8]) for early drift signal
path_a10 = os.path.join(evid, 'logits_force_A', 'd2_logits_pos10.bin')
path_b10 = os.path.join(evid, 'logits_force_B', 'd2_logits_pos10.bin')
A10, B10 = load(path_a10), load(path_b10)
max_abs10 = max(abs(A10[i]-B10[i]) for i in range(N))
print('POS10_MAX_ABS', max_abs10)
print('POS10_A_TOP1', topk(A10,1)[0], 'B_TOP1', topk(B10,1)[0])
