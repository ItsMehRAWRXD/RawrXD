import numpy as np

def load_bin(path, expected_count=102400):
    with open(path, 'rb') as f:
        data = f.read()
    if len(data) != expected_count * 4:
        raise ValueError(f"Expected {expected_count*4} bytes, got {len(data)}")
    return np.frombuffer(data, dtype=np.float32)

def compare_logits(native_path, ref_path, pos):
    native = load_bin(native_path)
    ref = load_bin(ref_path)
    
    print(f"\n=== Position {pos} Comparison ===")
    native_argmax = int(native.argmax())
    ref_argmax = int(ref.argmax())
    print(f"Native argmax: {native_argmax} (logit={native[native_argmax]:.6f})")
    print(f"Ref argmax:    {ref_argmax} (logit={ref[ref_argmax]:.6f})")
    print(f"Argmax match: {native_argmax == ref_argmax}")
    
    diff = native - ref
    abs_diff = np.abs(diff)
    print(f"Max abs diff: {abs_diff.max():.6f} at {abs_diff.argmax()}")
    print(f"RMSE: {np.sqrt(np.mean(diff*diff)):.6f}")
    print(f"Cosine: {np.dot(native, ref)/(np.linalg.norm(native)*np.linalg.norm(ref)):.10f}")
    
    # Top tokens
    native_top10 = np.argpartition(native, -10)[-10:]
    native_top10 = native_top10[np.argsort(native[native_top10])[::-1]]
    ref_top10 = np.argpartition(ref, -10)[-10:]
    ref_top10 = ref_top10[np.argsort(ref[ref_top10])[::-1]]
    print(f"Native top-10: {native_top10.tolist()}")
    print(f"Ref top-10:    {ref_top10.tolist()}")
    print(f"Top-10 overlap: {len(set(native_top10) & set(ref_top10))}/10")

# Compare position 2
compare_logits(
    r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\native_tf_logits_pos2.bin',
    r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\ref_logits_pos2.bin',
    2
)

# Compare position 3
compare_logits(
    r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\native_tf_logits_pos3.bin',
    r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\ref_logits_pos3.bin',
    3
)