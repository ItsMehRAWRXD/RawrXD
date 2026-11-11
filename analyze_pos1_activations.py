import numpy as np

def load_bin(path):
    with open(path, 'rb') as f:
        data = f.read()
    return np.frombuffer(data, dtype=np.float32)

native_dir = r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\parity_ir'

print("=== Native Position 1 Activations Analysis ===")
for op_id in range(13):
    path = f"{native_dir}\\op_{op_id:03d}.bin"
    try:
        arr = load_bin(path)
        print(f"op_{op_id:03d}: shape={arr.shape}, range=[{arr.min():.6f}, {arr.max():.6f}], mean={arr.mean():.6f}, std={arr.std():.6f}, norm={np.linalg.norm(arr):.6f}")
    except Exception as e:
        print(f"op_{op_id:03d}: ERROR - {e}")

# Compare position 0 vs position 1 for key operations
# We need to re-run position 0 to get fresh dumps, or use the old single-token run
print("\n=== Comparing Position 0 (single) vs Position 1 (multi) for First Block ===")
old_native_dir = r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\parity_ir_old'  # May not exist

# Let's check if we have old position 0 dumps
import os
for op_id in [0, 1, 2, 3, 4, 298, 299]:
    old_path = f"F:\\rawrxd\\evidence\\NUGVERSE_ESTIMATOR_001\\parity_ir\\op_{op_id:03d}.bin"
    new_path = f"F:\\rawrxd\\evidence\\NUGVERSE_ESTIMATOR_001\\parity_ir\\op_{op_id:03d}.bin"
    if os.path.exists(old_path) and os.path.exists(new_path):
        old_arr = load_bin(old_path)
        new_arr = load_bin(new_path)
        diff = new_arr - old_arr
        print(f"op_{op_id:03d}: old_range=[{old_arr.min():.6f}, {old_arr.max():.6f}], new_range=[{new_arr.min():.6f}, {new_arr.max():.6f}], max_diff={np.abs(diff).max():.6f}, rmse={np.sqrt(np.mean(diff*diff)):.6f}")
    else:
        print(f"op_{op_id:03d}: Old={os.path.exists(old_path)}, New={os.path.exists(new_path)}")