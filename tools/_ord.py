import numpy as np
# Is runtime q maybe in a different order: [head*dim] vs [dim*head]?
q = np.fromfile(r"F:\rawrxd\evidence\RAWRXD_DEEP2_RUNTIME_PARITY_001\dump\t_lin3_pos1.bin", dtype=np.float32).astype(np.float64)
g = np.fromfile(r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1\rec_000010_op3_Linear_Output_l0_p1_output.bin", dtype=np.float32).astype(np.float64)[32:32+3072]
def cos(a,b):
    a=np.asarray(a,dtype=np.float64); b=np.asarray(b,dtype=np.float64)
    return float(a@b/(np.linalg.norm(a)*np.linalg.norm(b)))
print('sizes', q.size, g.size)
# hypothesis: g is [head][dim] contiguous, q might be [dim][head]
g16 = g.reshape(16,192)
q_as_dimhead = q.reshape(192,16).T  # if runtime wrote transposed
print('cos(q as [head][dim], g)   = %.6f' % cos(q, g))
print('cos(q.T (from [dim][head]), g) = %.6f' % cos(q_as_dimhead, g))
print()
print('g first 8 :', ['%.4f'%x for x in g[:8]])
print('q first 8 :', ['%.4f'%x for x in q[:8]])
print()
print('g head0[0:8] :', ['%.4f'%x for x in g16[0,:8]])
print('q head0[0:8] :', ['%.4f'%x for x in q.reshape(16,192)[0,:8]])
print('q dim0      :', ['%.4f'%x for x in q.reshape(192,16)[:8,0]])