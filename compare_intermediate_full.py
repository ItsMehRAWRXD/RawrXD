import numpy as np
import struct

def load_bin(path):
    with open(path, 'rb') as f:
        data = f.read()
    return np.frombuffer(data, dtype=np.float32)

def compare_activations(native_path, ref_path, name, expected_shape=None):
    native = load_bin(native_path)
    ref = load_bin(ref_path)
    
    if expected_shape and native.shape != expected_shape:
        print(f"  {name}: SHAPE MISMATCH native={native.shape} ref={ref.shape} expected={expected_shape}")
        return None
    
    if native.shape != ref.shape:
        print(f"  {name}: SHAPE MISMATCH native={native.shape} ref={ref.shape}")
        return None
    
    diff = native - ref
    abs_diff = np.abs(diff)
    max_abs_diff = abs_diff.max()
    rmse = np.sqrt(np.mean(diff * diff))
    mean_abs = abs_diff.mean()
    
    dot = np.dot(native, ref)
    norm_native = np.linalg.norm(native)
    norm_ref = np.linalg.norm(ref)
    cos_sim = dot / (norm_native * norm_ref) if norm_native > 0 and norm_ref > 0 else 0
    
    print(f"  {name}: shape={native.shape}, max_diff={max_abs_diff:.6f}, rmse={rmse:.6f}, mean_abs={mean_abs:.6f}, cos_sim={cos_sim:.10f}")
    
    return {
        'name': name,
        'shape': native.shape,
        'max_abs_diff': float(max_abs_diff),
        'rmse': float(rmse),
        'mean_abs_diff': float(mean_abs),
        'cosine_sim': float(cos_sim)
    }

if __name__ == '__main__':
    native_dir = r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\parity_ir'
    ref_dir = r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001'
    
    # First block operations at position 1
    # op 0: embedding (2048)
    # op 1: RMSNorm (2048)
    # op 2: MLA Decompress (5120)
    # op 3: Q Projection (3072)
    # op 4: Attention (2048)
    # op 5: O Projection (2048)
    # op 6: ResidualAdd (2048)
    # op 7: RMSNorm (2048)
    # op 8: Gate (10944)
    # op 9: Up (10944)
    # op 10: GateUp/SiLU (2048)
    # op 11: Down (2048)
    # op 12: ResidualAdd (2048)
    
    print("=== Position 1 First Block Activation Comparison ===")
    
    ops = [
        (0, "Embedding", 2048),
        (1, "RMSNorm_1", 2048),
        (2, "MLA_Decompress", 5120),
        (3, "Q_Projection", 3072),
        (4, "Attention", 2048),
        (5, "O_Projection", 2048),
        (6, "ResidualAdd_1", 2048),
        (7, "RMSNorm_2", 2048),
        (8, "Gate", 10944),
        (9, "Up", 10944),
        (10, "GateUp_SiLU", 2048),
        (11, "Down", 2048),
        (12, "ResidualAdd_2", 2048),
    ]
    
    results = []
    for op_id, name, expected_size in ops:
        native_file = f"{native_dir}\\op_{op_id:03d}.bin"
        ref_file = f"{ref_dir}\\ref_op_{op_id:03d}_pos1.bin"
        try:
            r = compare_activations(native_file, ref_file, name, (expected_size,))
            if r:
                results.append(r)
        except FileNotFoundError as e:
            print(f"  {name}: FILE NOT FOUND - {e}")
        except Exception as e:
            print(f"  {name}: ERROR - {e}")
    
    # Also compare final hidden state (op 298) and logits (op 299)
    print("\n=== Final Layers ===")
    for op_id, name, expected_size in [(298, "Final_Hidden", 2048), (299, "Logits", 102400)]:
        native_file = f"{native_dir}\\op_{op_id:03d}.bin"
        ref_file = f"{ref_dir}\\ref_op_{op_id:03d}_pos1.bin"
        try:
            r = compare_activations(native_file, ref_file, name, (expected_size,))
            if r:
                results.append(r)
        except FileNotFoundError as e:
            print(f"  {name}: FILE NOT FOUND - {e}")
        except Exception as e:
            print(f"  {name}: ERROR - {e}")
    
    # Save summary
    import json
    with open(r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\intermediate_comparison.json', 'w') as f:
        json.dump(results, f, indent=2)
    print("\nResults saved to intermediate_comparison.json")