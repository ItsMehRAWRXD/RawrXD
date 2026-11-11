import numpy as np
import struct

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
    
    print(f"\n=== Position {pos} Comparison ===")
    print(f"Native shape: {native.shape}, Ref shape: {ref.shape}")
    print(f"Native range: [{native.min():.6f}, {native.max():.6f}], mean={native.mean():.6f}")
    print(f"Ref range:    [{ref.min():.6f}, {ref.max():.6f}], mean={ref.mean():.6f}")
    
    # Argmax
    native_argmax = int(native.argmax())
    ref_argmax = int(ref.argmax())
    print(f"\nNative argmax: {native_argmax} (logit={native[native_argmax]:.6f})")
    print(f"Ref argmax:    {ref_argmax} (logit={ref[ref_argmax]:.6f})")
    print(f"Argmax match: {native_argmax == ref_argmax}")
    
    # Differences
    diff = native - ref
    abs_diff = np.abs(diff)
    max_abs_diff = abs_diff.max()
    rmse = np.sqrt(np.mean(diff * diff))
    
    print(f"\nMax absolute difference: {max_abs_diff:.6f} at index {abs_diff.argmax()}")
    print(f"RMSE: {rmse:.6f}")
    print(f"Mean abs diff: {abs_diff.mean():.6f}")
    print(f"Median abs diff: {np.median(abs_diff):.6f}")
    print(f"99th percentile abs diff: {np.percentile(abs_diff, 99):.6f}")
    
    # Cosine similarity
    dot = np.dot(native, ref)
    norm_native = np.linalg.norm(native)
    norm_ref = np.linalg.norm(ref)
    cos_sim = dot / (norm_native * norm_ref)
    print(f"Cosine similarity: {cos_sim:.10f}")
    
    # Specific tokens
    print(f"\nToken 185: native={native[185]:.6f}, ref={ref[185]:.6f}, diff={abs_diff[185]:.6f}")
    print(f"Token 93633: native={native[93633]:.6f}, ref={ref[93633]:.6f}, diff={abs_diff[93633]:.6f}")
    
    # Top-10 agreement
    native_top10 = np.argpartition(native, -10)[-10:]
    native_top10 = native_top10[np.argsort(native[native_top10])[::-1]]
    ref_top10 = np.argpartition(ref, -10)[-10:]
    ref_top10 = ref_top10[np.argsort(ref[ref_top10])[::-1]]
    
    print(f"\nNative top-10: {native_top10.tolist()}")
    print(f"Ref top-10:    {ref_top10.tolist()}")
    
    top10_overlap = len(set(native_top10) & set(ref_top10))
    print(f"Top-10 overlap: {top10_overlap}/10")
    
    # Top-100 agreement
    native_top100 = set(np.argpartition(native, -100)[-100:])
    ref_top100 = set(np.argpartition(ref, -100)[-100:])
    top100_overlap = len(native_top100 & ref_top100)
    print(f"Top-100 overlap: {top100_overlap}/100")
    
    return {
        'pos': pos,
        'native_argmax': native_argmax,
        'ref_argmax': ref_argmax,
        'argmax_match': native_argmax == ref_argmax,
        'max_abs_diff': float(max_abs_diff),
        'rmse': float(rmse),
        'cosine_sim': float(cos_sim),
        'diff_at_185': float(abs_diff[185]),
        'diff_at_93633': float(abs_diff[93633]),
        'top10_overlap': top10_overlap,
        'top100_overlap': top100_overlap,
        'mean_abs_diff': float(abs_diff.mean()),
        'median_abs_diff': float(np.median(abs_diff)),
        'p99_abs_diff': float(np.percentile(abs_diff, 99))
    }

if __name__ == '__main__':
    results = compare_logits(
        r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\native_logits_pos1_fixed.bin',
        r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\ref_logits_pos1.bin',
        1
    )
    
    import json
    with open(r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\pos1_comparison_fixed.json', 'w') as f:
        json.dump(results, f, indent=2)
    print("\nResults written to pos1_comparison_fixed.json")