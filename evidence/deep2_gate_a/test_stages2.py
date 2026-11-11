import os
import numpy as np

D2 = r"F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone"
REF = r"F:\rawrxd\evidence\deep2_gate_a\ref_intermediate_v2"

def load_bin(p): 
    with open(p,'rb') as f: return np.frombuffer(f.read(),dtype='<f4').astype(np.float64)

trace = {}
with open(os.path.join(D2,"d2_trace_pos10.txt")) as f:
    for line in f:
        if line.startswith('blk='):
            p=line.strip().split()
            trace[(int(p[0].split('=')[1]),p[3].split('=')[1])]=int(p[1].split('=')[1])

def d2f(name, layer=0, pos=10):
    blk = 999 if layer < 0 else layer
    pc = trace.get((layer,name),0)
    t = name.replace('_','')
    path=os.path.join(D2,f"d2_pos{pos}_blk{blk}_pc{pc}_{name}.bin")
    if not os.path.exists(path):
        # try sanitized
        path=os.path.join(D2,f"d2_pos{pos}_blk{blk}_pc{pc}_{t}.bin")
    return load_bin(path) if os.path.exists(path) else None

def refst(name, layer, stage):
    if stage==0:
        return os.path.join(REF,f"ref_pos10_layer{layer}_{name}_layer{layer}.bin")
    return os.path.join(REF,f"ref_pos10_layer{layer}_{name}_layer{layer}_stage{stage}.bin")

# Test attn_norm stages
d2n = d2f('attn_norm',0)
for s in [0,1]:
    pth = refst('attn_norm',0,s)
    if os.path.exists(pth):
        r = load_bin(pth)
        c = np.dot(d2n,r)/(np.linalg.norm(d2n)*np.linalg.norm(r))
        print(f"attn_norm stage{s}: cos={c:.8f} shape={r.shape}")

# Test gate stages
d2g = d2f('gate',0)
for s in [0,1]:
    pth = refst('gate',0,s)
    if os.path.exists(pth):
        r = load_bin(pth)
        c = np.dot(d2g,r)/(np.linalg.norm(d2g)*np.linalg.norm(r))
        print(f"gate stage{s}: cos={c:.8f} shape={r.shape}")

# Test up stages
d2u = d2f('up',0)
for s in [0,1]:
    pth = refst('up',0,s)
    if os.path.exists(pth):
        r = load_bin(pth)
        c = np.dot(d2u,r)/(np.linalg.norm(d2u)*np.linalg.norm(r))
        print(f"up stage{s}: cos={c:.8f} shape={r.shape}")

# Test ffn_norm
d2fn = d2f('ffn_norm',0)
for s in [0,1]:
    pth = refst('ffn_norm',0,s)
    if os.path.exists(pth):
        r = load_bin(pth)
        c = np.dot(d2fn,r)/(np.linalg.norm(d2fn)*np.linalg.norm(r))
        print(f"ffn_norm stage{s}: cos={c:.8f}")

# Test swiglu
d2s = d2f('swiglu',0)
for s in [0,1]:
    pth = refst('swiglu',0,s)
    if os.path.exists(pth):
        r = load_bin(pth)
        c = np.dot(d2s,r)/(np.linalg.norm(d2s)*np.linalg.norm(r))
        print(f"swiglu stage{s}: cos={c:.8f}")

# Test ffn_out
d2fo = d2f('ffn_out',0)
for s in [0,1]:
    pth = refst('ffn_out',0,s)
    if os.path.exists(pth):
        r = load_bin(pth)
        c = np.dot(d2fo,r)/(np.linalg.norm(d2fo)*np.linalg.norm(r))
        print(f"ffn_out stage{s}: cos={c:.8f}")

# Test embd - is it the right tensor?
d2e = d2f('token_embd.weight',-1)
print(f"\nDeep2 embd shape: {d2e.shape if d2e is not None else None}")
# llama embd is the INPUT embedding
for s in [0]:
    pth = os.path.join(REF,f"ref_pos10_layer-1_embd.bin")
    if os.path.exists(pth):
        r = load_bin(pth)
        print(f"ref embd shape: {r.shape}")
        if d2e is not None and r.shape==d2e.shape:
            c = np.dot(d2e,r)/(np.linalg.norm(d2e)*np.linalg.norm(r))
            print(f"embd cos={c:.8f}")

# attn_out stages
d2ao = d2f('attn_out',0)
import glob
for f in sorted(glob.glob(os.path.join(REF,"ref_pos10_layer0_attn_out*"))):
    r = load_bin(f)
    if d2ao is not None and r.shape==d2ao.shape:
        c = np.dot(d2ao,r)/(np.linalg.norm(d2ao)*np.linalg.norm(r))
        print(f"attn_out {os.path.basename(f)}: cos={c:.8f}")
