import numpy as np

native = np.frombuffer(open(r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\native_logits_pos1_diag.bin', 'rb').read(), dtype=np.float32)
ref = np.frombuffer(open(r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\ref_logits_pos1.bin', 'rb').read(), dtype=np.float32)

diff = native - ref

print("=== Difference Distribution ===")
print(f"Mean diff: {diff.mean():.6f}")
print(f"Std diff:  {diff.std():.6f}")
print(f"Min diff:  {diff.min():.6f} at {diff.argmin()}")
print(f"Max diff:  {diff.max():.6f} at {diff.argmax()}")

# Check sign distribution
pos_diff = diff[diff > 0]
neg_diff = diff[diff < 0]
print(f"\nPositive diffs: {len(pos_diff)} (mean={pos_diff.mean():.6f}, max={pos_diff.max():.6f})")
print(f"Negative diffs: {len(neg_diff)} (mean={neg_diff.mean():.6f}, min={neg_diff.min():.6f})")

# Top tokens where native > ref
top_pos = np.argsort(diff)[-20:]
print(f"\nTop 20 where native > ref:")
for idx in top_pos:
    print(f"  token {idx:6d}: native={native[idx]:.6f}, ref={ref[idx]:.6f}, diff={diff[idx]:.6f}")

# Top tokens where ref > native
top_neg = np.argsort(diff)[:20]
print(f"\nTop 20 where ref > native:")
for idx in top_neg:
    print(f"  token {idx:6d}: native={native[idx]:.6f}, ref={ref[idx]:.6f}, diff={diff[idx]:.6f}")

# Check if it's a simple scaling
# If native = a * ref + b, what are a, b?
# Linear regression
mask = np.isfinite(native) & np.isfinite(ref)
n = native[mask]
r = ref[mask]
a = np.cov(n, r)[0,1] / np.var(r)
b = n.mean() - a * r.mean()
print(f"\nLinear fit: native = {a:.6f} * ref + {b:.6f}")

# Predictions
pred = a * r + b
residual = n - pred
print(f"Residual RMSE: {np.sqrt(np.mean(residual*residual)):.6f}")
print(f"Residual max:  {np.max(np.abs(residual)):.6f}")

# Check specific problematic tokens
problem_tokens = [1, 6, 185, 790, 35643, 9213, 100001, 44756]
print(f"\nProblem tokens detail:")
for t in problem_tokens:
    if t < len(native):
        print(f"  token {t:6d}: native={native[t]:.6f}, ref={ref[t]:.6f}, diff={diff[t]:.6f}, pred={a*ref[t]+b:.6f}, resid={native[t]-(a*ref[t]+b):.6f}")