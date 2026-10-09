import numpy as np
import json

def load_bin(path, expected_count=102400):
    with open(path, 'rb') as f:
        data = f.read()
    if len(data) != expected_count * 4:
        raise ValueError(f"Expected {expected_count*4} bytes, got {len(data)}")
    return np.frombuffer(data, dtype=np.float32)

native = load_bin(r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\native_logits_pos1_diag.bin')
ref = load_bin(r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\ref_logits_pos1.bin')

print("=== Position 1 Detailed Logit Comparison ===")
print(f"Native: argmax={native.argmax()} (logit={native[native.argmax()]:.6f})")
print(f"Ref:    argmax={ref.argmax()} (logit={ref[ref.argmax()]:.6f})")

# Top-2 logits
print(f"\nTop-2 tokens:")
print(f"  Token 1:   native={native[1]:.6f}, ref={ref[1]:.6f}, diff={abs(native[1]-ref[1]):.6f}")
print(f"  Token 185: native={native[185]:.6f}, ref={ref[185]:.6f}, diff={abs(native[185]-ref[185]):.6f}")

# Margins
native_margin = native[185] - native[1]
ref_margin = ref[185] - ref[1]
print(f"\nMargins (logit_185 - logit_1):")
print(f"  Native:  {native_margin:.6f}")
print(f"  Ref:     {ref_margin:.6f}")
print(f"  Diff:    {abs(native_margin - ref_margin):.6f}")

# Full stats
diff = native - ref
abs_diff = np.abs(diff)
print(f"\nFull logit stats:")
print(f"  Max abs diff: {abs_diff.max():.6f} at {abs_diff.argmax()}")
print(f"  RMSE: {np.sqrt(np.mean(diff*diff)):.6f}")
print(f"  Cosine: {np.dot(native, ref)/(np.linalg.norm(native)*np.linalg.norm(ref)):.10f}")

# Top-10
native_top10 = np.argpartition(native, -10)[-10:]
native_top10 = native_top10[np.argsort(native[native_top10])[::-1]]
ref_top10 = np.argpartition(ref, -10)[-10:]
ref_top10 = ref_top10[np.argsort(ref[ref_top10])[::-1]]

print(f"\nNative top-10:")
for i, idx in enumerate(native_top10):
    print(f"  {i+1:2d}. token {idx:6d}: native={native[idx]:.6f}, ref={ref[idx]:.6f}, diff={abs(native[idx]-ref[idx]):.6f}")

print(f"\nRef top-10:")
for i, idx in enumerate(ref_top10):
    print(f"  {i+1:2d}. token {idx:6d}: ref={ref[idx]:.6f}, native={native[idx]:.6f}, diff={abs(native[idx]-ref[idx]):.6f}")

# Rank of tokens 1 and 185
native_rank_1 = np.sum(native > native[1]) + 1
native_rank_185 = np.sum(native > native[185]) + 1
ref_rank_1 = np.sum(ref > ref[1]) + 1
ref_rank_185 = np.sum(ref > ref[185]) + 1

print(f"\nRanks:")
print(f"  Token 1:   native rank={native_rank_1}, ref rank={ref_rank_1}")
print(f"  Token 185: native rank={native_rank_185}, ref rank={ref_rank_185}")

# Top-k overlap for various k
for k in [5, 10, 20, 50, 100]:
    native_topk = set(np.argpartition(native, -k)[-k:])
    ref_topk = set(np.argpartition(ref, -k)[-k:])
    overlap = len(native_topk & ref_topk)
    print(f"  Top-{k} overlap: {overlap}/{k}")

# Save detailed results
results = {
    'native_argmax': int(native.argmax()),
    'ref_argmax': int(ref.argmax()),
    'native_top2': [int(native_top10[-1]), int(native_top10[-2])] if len(native_top10) >= 2 else [],
    'ref_top2': [int(ref_top10[-1]), int(ref_top10[-2])] if len(ref_top10) >= 2 else [],
    'native_logit_1': float(native[1]),
    'ref_logit_1': float(ref[1]),
    'native_logit_185': float(native[185]),
    'ref_logit_185': float(ref[185]),
    'native_margin': float(native_margin),
    'ref_margin': float(ref_margin),
    'cosine': float(np.dot(native, ref)/(np.linalg.norm(native)*np.linalg.norm(ref))),
    'rmse': float(np.sqrt(np.mean(diff*diff))),
    'max_abs_diff': float(abs_diff.max()),
    'native_rank_1': int(native_rank_1),
    'ref_rank_1': int(ref_rank_1),
    'native_rank_185': int(native_rank_185),
    'ref_rank_185': int(ref_rank_185),
}

with open(r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\pos1_detailed_comparison.json', 'w') as f:
    json.dump(results, f, indent=2)

print("\nResults saved to pos1_detailed_comparison.json")