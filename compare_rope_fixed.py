import numpy as np

def load_bin(path, expected_count=102400):
    with open(path, 'rb') as f:
        data = f.read()
    if len(data) != expected_count * 4:
        raise ValueError(f"Expected {expected_count*4} bytes, got {len(data)}")
    arr = np.frombuffer(data, dtype=np.float32)
    if arr.shape[0] != expected_count:
        raise ValueError(f"Expected {expected_count} floats, got {arr.shape[0]}")
    return arr

def compare_logits(native_path, ref_path, pos):
    native = load_bin(native_path)
    ref = load_bin(ref_path)
    
    print(f"\n=== Position {pos} Comparison (RoPE Fixed) ===")
    native_argmax = int(native.argmax())
    ref_argmax = int(ref.argmax())
    print(f"Native argmax: {native_argmax} (logit={native[native_argmax]:.6f})")
    print(f"Ref argmax:    {ref_argmax} (logit={ref[ref_argmax]:.6f})")
    print(f"Argmax match: {native_argmax == ref_argmax}")
    
    diff = native - ref
    abs_diff = np.abs(diff)
    max_abs_diff = abs_diff.max()
    rmse = np.sqrt(np.mean(diff * diff))
    
    print(f"Max abs diff: {max_abs_diff:.6f} at {abs_diff.argmax()}")
    print(f"RMSE: {rmse:.6f}")
    print(f"Mean abs diff: {abs_diff.mean():.6f}")
    
    dot = np.dot(native, ref)
    norm_native = np.linalg.norm(native)
    norm_ref = np.linalg.norm(ref)
    cos_sim = dot / (norm_native * norm_ref)
    print(f"Cosine similarity: {cos_sim:.10f}")
    
    # Top-10
    native_top10 = np.argpartition(native, -10)[-10:]
    native_top10 = native_top10[np.argsort(native[native_top10])[::-1]]
    ref_top10 = np.argpartition(ref, -10)[-10:]
    ref_top10 = ref_top10[np.argsort(ref[ref_top10])[::-1]]
    
    print(f"\nNative top-10: {native_top10.tolist()}")
    print(f"Ref top-10:    {ref_top10.tolist()}")
    
    top10_overlap = len(set(native_top10) & set(ref_top10))
    print(f"Top-10 overlap: {top10_overlap}/10")
    
    # Margins
    print(f"\nMargins (185 - 1): native={native[185]-native[1]:.6f}, ref={ref[185]-ref[1]:.6f}")

if __name__ == '__main__':
    compare_logits(
        r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\native_tf_logits_pos2.bin',
        r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\ref_logits_pos2.bin',
        2
    )
    compare_logits(
        r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\native_tf_logits_pos3.bin',
        r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\ref_logits_pos3.bin',
        3
    )