#!/usr/bin/env python3
"""
Test the permutation hypothesis: are Deep2 Q values the same as reference Q values but in different order?
"""
import os
import numpy as np

D2 = r"F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone"
REF = r"F:\rawrxd\evidence\deep2_gate_a\ref_intermediate_full"

def load_bin(path, dtype='<f4'):
    with open(path, 'rb') as f:
        data = f.read()
    return np.frombuffer(data, dtype=dtype).astype(np.float64)

def find_tensor_file(pos, blk, pc, name):
    def sanitize(s):
        return ''.join(c if (c.isalnum() or c in '-_.') else '_' for c in name)
    clean_name = sanitize(name)
    blk_str = str(blk) if blk >= 0 else "999"
    path = os.path.join(D2, f"d2_pos{pos}_blk{blk_str}_pc{pc}_{clean_name}.bin")
    return path if os.path.exists(path) else None

# Load Q projections at position 10
trace10_path = os.path.join(D2, "d2_trace_pos10.txt")
trace10_map = {}
with open(trace10_path, 'r') as f:
    for line in f:
        if line.startswith('blk='):
            parts = line.strip().split()
            blk = int(parts[0].split('=')[1])
            pc = int(parts[1].split('=')[1])
            name = parts[3].split('=')[1]
            trace10_map[(blk, name)] = pc

d2_q = load_bin(find_tensor_file(10, 0, trace10_map[(0, 'q')], 'q'))
ref_q = load_bin(os.path.join(REF, "ref_pos10_layer0_q_layer0.bin"))

print("=== Permutation hypothesis test ===")
print(f"Indexed cosine:  {np.dot(d2_q, ref_q)/(np.linalg.norm(d2_q)*np.linalg.norm(ref_q)):.6f}")
print(f"Indexed RMSE:    {np.sqrt(np.mean((d2_q - ref_q)**2)):.6f}")

# Sorted comparison
sorted_ref = np.sort(ref_q)
sorted_d2 = np.sort(d2_q)
sorted_diff = sorted_ref - sorted_d2
sorted_rmse = np.sqrt(np.mean(sorted_diff**2))
print(f"\nSorted RMSE:     {sorted_rmse:.6f}")
print(f"Sorted maxabs:   {np.max(np.abs(sorted_diff)):.6f}")
sorted_cos = np.dot(sorted_ref, sorted_d2)/(np.linalg.norm(sorted_ref)*np.linalg.norm(sorted_d2))
print(f"Sorted cosine:   {sorted_cos:.6f}")

# Check if sets match (with tolerance)
sorted_ref_set = set(np.round(sorted_ref, 3))
sorted_d2_set = set(np.round(sorted_d2, 3))
print(f"\nSet intersection size: {len(sorted_ref_set & sorted_d2_set)}")
print(f"Ref unique (rounded): {len(sorted_ref_set)}")
print(f"D2 unique (rounded):  {len(sorted_d2_set)}")

# Test specific Llama head permutation: [128,24] -> permute head pairs
# Llama uses odd-even head pair permutation: (h, h+24/2) for h < 24/2
print("\n=== Llama head permutation test ===")
# Q is [3072] reshaped to [24 heads, 128 head_dim] = [24, 128]
# Llama permutes heads: pairs (i, i+12) where i=0..11
d2_q_2d = d2_q.reshape(24, 128)
ref_q_2d = ref_q.reshape(24, 128)

# Try various permutations of the head dimension
# Option 1: swap head pairs (i <-> i+12)
perm1 = list(range(12, 24)) + list(range(0, 12))  # [12,13,...,23,0,1,...,11]
d2_perm1 = d2_q_2d[perm1].flatten()
cos1 = np.dot(d2_perm1, ref_q)/(np.linalg.norm(d2_perm1)*np.linalg.norm(ref_q))
print(f"Head-pair swap (12<->0): cosine={cos1:.6f}")

# Option 2: reverse head order
perm2 = list(range(23, -1, -1))
d2_perm2 = d2_q_2d[perm2].flatten()
cos2 = np.dot(d2_perm2, ref_q)/(np.linalg.norm(d2_perm2)*np.linalg.norm(ref_q))
print(f"Head-reverse: cosine={cos2:.6f}")

# Option 3: Llama 3 style permutation: permute within each pair of halves
# Llama 3 rotates pairs: for i in range(n_heads//2): swap row i and row i+n_heads//2
perm3 = []
for i in range(24):
    if i < 12:
        perm3.append(i + 12)
    else:
        perm3.append(i - 12)
d2_perm3 = d2_q_2d[perm3].flatten()
cos3 = np.dot(d2_perm3, ref_q)/(np.linalg.norm(d2_perm3)*np.linalg.norm(ref_q))
print(f"Llama3 head rotation: cosine={cos3:.6f}")

# Option 4: try [128,24] layout instead of [24,128] then transpose
d2_q_alt = d2_q.reshape(128, 24).T.flatten()
cos4 = np.dot(d2_q_alt, ref_q)/(np.linalg.norm(d2_q_alt)*np.linalg.norm(ref_q))
print(f"Transpose [128,24]->[24,128]: cosine={cos4:.6f}")

# Option 5: check if it's a byte-order or element-order swap
d2_q_rev = d2_q[::-1]
cos5 = np.dot(d2_q_rev, ref_q)/(np.linalg.norm(d2_q_rev)*np.linalg.norm(ref_q))
print(f"Full reverse: cosine={cos5:.6f}")

# Test within head_dim: swap pairs of elements (RoPE style)
print("\n=== Within-head-dim permutation test ===")
d2_q_3d = d2_q.reshape(24, 128)
ref_q_3d = ref_q.reshape(24, 128)

# Try swapping elements in pairs within each head (0<->1, 2<->3, ...)
perm6 = list(range(0, 128, 2)) + list(range(1, 128, 2))  # even then odd
d2_perm6 = d2_q_3d[:, perm6].flatten()
cos6 = np.dot(d2_perm6, ref_q)/(np.linalg.norm(d2_perm6)*np.linalg.norm(ref_q))
print(f"Even-odd pair swap: cosine={cos6:.6f}")

# Try interleaved: [0,2,4,...,1,3,5,...] per head
perm7 = list(range(0, 128, 2)) + list(range(1, 128, 2))
# Same as above

# Try: reshape to [24,64,2], swap last dim, flatten
d2_perm8 = d2_q_3d.reshape(24, 64, 2)[:, :, ::-1].reshape(24, 128).flatten()
cos8 = np.dot(d2_perm8, ref_q)/(np.linalg.norm(d2_perm8)*np.linalg.norm(ref_q))
print(f"Swap within pairs (RoPE): cosine={cos8:.6f}")

# Try: [24,2,64] swap middle
d2_perm9 = d2_q_3d.reshape(24, 2, 64)[:, ::-1, :].reshape(24, 128).flatten()
cos9 = np.dot(d2_perm9, ref_q)/(np.linalg.norm(d2_perm9)*np.linalg.norm(ref_q))
print(f"Swap halves (64<->64): cosine={cos9:.6f}")

# Try half-head swap: [128] -> [64,2] swap
d2_perm10 = d2_q_3d.reshape(24, 128).reshape(-1, 2, 64)[:, ::-1, :].reshape(-1).flatten()
cos10 = np.dot(d2_perm10, ref_q)/(np.linalg.norm(d2_perm10)*np.linalg.norm(ref_q))
print(f"Swap half-heads 64: cosine={cos10:.6f}")

# Try: full [3072] reshape [24,128] -> permute heads by stride 2
perm11 = list(range(0, 24, 2)) + list(range(1, 24, 2))
d2_perm11 = d2_q_3d[perm11].flatten()
cos11 = np.dot(d2_perm11, ref_q)/(np.linalg.norm(d2_perm11)*np.linalg.norm(ref_q))
print(f"Head stride-2: cosine={cos11:.6f}")

print("\n=== Direct element match test ===")
# Find how many elements match exactly (within tolerance)
d2_set = set(np.round(d2_q, 2).tolist())
ref_set = set(np.round(ref_q, 2).tolist())
match_count = len(d2_set & ref_set)
print(f"Elements matching (rounded to 2dp): {match_count}/{len(d2_set)} in D2, {match_count}/{len(ref_set)} in REF")

# Check first element of each head
print("\n=== First element of each head ===")
for h in range(6):
    print(f"  Head {h}: D2={d2_q[h*128]:10.4f}, Ref={ref_q[h*128]:10.4f}")