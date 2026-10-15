import struct, os
import numpy as np
import gguf

MODEL = r'F:\rawrxd\llama3.2-3b-Q2_K.gguf'
reader = gguf.GGUFReader(MODEL)
for t in reader.tensors:
    if t.name == 'blk.0.ffn_down.weight':
        td = t
        break
b = bytes(td.data)

def f16s(u):
    return float(np.frombuffer(struct.pack('<H', int(u)), dtype=np.float16)[0])

kmask1 = 0x03030303
kmask2 = 0x0f0f0f0f

def unpack_scales(sc12):
    a0, a1, a2 = struct.unpack('<III', bytes(sc12))
    aux = [0, 0, 0, 0]
    tmp = a2
    aux[2] = ((a0 >> 4) & kmask2) | (((tmp >> 4) & kmask1) << 4)
    aux[3] = ((a1 >> 4) & kmask2) | (((tmp >> 6) & kmask1) << 4)
    aux[0] = (a0 & kmask2) | (((tmp >> 0) & kmask1) << 4)
    aux[1] = (a1 & kmask2) | (((tmp >> 2) & kmask1) << 4)
    return np.frombuffer(struct.pack('<IIII', *aux), dtype=np.int8).astype(np.int32)

def dequant_block(bi):
    o = bi * 110
    hmask = np.frombuffer(b[o:o + 32], dtype=np.uint8).astype(np.int32)
    qs = np.frombuffer(b[o + 32:o + 96], dtype=np.uint8).astype(np.int32)
    scales = unpack_scales(b[o + 96:o + 108])
    d = f16s(struct.unpack_from('<H', b, o + 108)[0])
    out = np.zeros(256)
    is_ = 0
    for n in range(0, 256, 128):
        qbase = (n // 128) * 32
        m = 1 << (4 * (n // 128))
        for jsub in range(4):
            shift = 2 * jsub
            dl = d * float(scales[is_]); is_ += 1
            for l in range(32):
                w = n + jsub * 32 + l
                out[w] = dl * (float((qs[qbase + l] >> shift) & 3) -
                               (0.0 if (hmask[l] & m) else 4.0))
            m <<= 1
    return out

D2 = r'F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone'
tr = {}
with open(os.path.join(D2, 'd2_trace_pos10.txt')) as f:
    for line in f:
        if line.startswith('blk='):
            q = line.strip().split()
            tr[(int(q[0].split('=')[1]), q[3].split('=')[1])] = int(q[1].split('=')[1])
sw = tr[(0, 'swiglu')]
x = np.frombuffer(open(os.path.join(D2, f'd2_pos10_blk0_pc{sw}_swiglu.bin'), 'rb').read(),
                  dtype='<f4').astype(np.float64)
fo = tr[(0, 'ffn_out')]
d2out = np.frombuffer(open(os.path.join(D2, f'd2_pos10_blk0_pc{fo}_ffn_out.bin'), 'rb').read(),
                      dtype='<f4').astype(np.float64)

total_blocks = len(b) // 110
print('total blocks', total_blocks, '(= 3072 rows x 32)')

# Brute force: for output neuron 0, try candidate row starts
target = d2out[0]
print(f'Target D2 ffn_out[0] = {target:.8f}')
print('\nTrying contiguous row starts (blocks k*32 .. k*32+31):')
best = []
for k in range(0, 64):
    W = np.concatenate([dequant_block(k * 32 + j) for j in range(32)])
    y = float(W @ x)
    if abs(y - target) < 0.002:
        print(f'  MATCH row_start_block={k*32} (row {k}): y={y:.8f}')
    best.append((abs(y - target), k, y))
best.sort()
print('closest contiguous rows:', [(f'row{k}', f'{y:.6f}') for _, k, y in best[:5]])
