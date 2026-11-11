import numpy as np
import struct

def load_bin(path):
    with open(path, 'rb') as f:
        data = f.read()
    arr = np.frombuffer(data, dtype=np.float32)
    return arr

def compare_activations(native_path, ref_path, name):
    native = load_bin(native_path)
    ref = load_bin(ref_path)
    
    if native.shape != ref.shape:
        print(f"  {name}: SHAPE MISMATCH native={native.shape} ref={ref.shape}")
        return False
    
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
    
    return max_abs_diff < 1e-3

if __name__ == '__main__':
    # Native position 1 activations (from 2-token run)
    native_dir = r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\parity_ir'
    ref_dir = r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001'
    
    # First block operations (op 0-11 for position 1)
    # Note: These are from the 2-token run, but we need to identify which are position 1
    # The dumps are from the last run which was 2 tokens, so they should be position 1
    print("=== First Block Position 1 Comparison ===")
    
    ops = [
        (0, "Embedding", 2048),
        (1, "RMSNorm_1", 2048),
        (2, "MLA_Decompress", 5120),  # K/V expanded
        (3, "Q_Projection", 3072),
        (4, "Attention", 2048),
        (5, "O_Projection", 2048),
        (6, "ResidualAdd_1", 2048),
        (7, "RMSNorm_2", 2048),
        (8, "Gate", 10944),
        (9, "Up", 10944),
        (10, "GateUp", 2048),
        (11, "Down", 2048),
    ]
    
    for op_id, name, expected_size in ops:
        native_file = f"{native_dir}\\op_{op_id:03d}.bin"
        ref_file = f"{ref_dir}\\ref_op_{op_id:03d}_pos1.bin"
        try:
            compare_activations(native_file, ref_file, name)
        except FileNotFoundError as e:
            print(f"  {name}: FILE NOT FOUND - {e}")
        except Exception as e:
            print(f"  {name}: ERROR - {e}")