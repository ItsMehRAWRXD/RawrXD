import numpy as np
import struct

def load_bin(path):
    with open(path, 'rb') as f:
        data = f.read()
    return np.frombuffer(data, dtype=np.float32)

# Load native position 1 activations (from 2-token run)
native_dir = r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\parity_ir'
ref_dir = r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001'

# Load all native ops for first block
print("=== Native Position 1 First Block Activations ===")
for op_id in range(12):
    path = f"{native_dir}\\op_{op_id:03d}.bin"
    try:
        arr = load_bin(path)
        print(f"  op_{op_id:03d}: shape={arr.shape}, range=[{arr.min():.6f}, {arr.max():.6f}], mean={arr.mean():.6f}, norm={np.linalg.norm(arr):.6f}")
    except Exception as e:
        print(f"  op_{op_id:03d}: ERROR - {e}")

print("\n=== Reference Position 0 Logits ===")
ref_pos0 = load_bin(f"{ref_dir}\\ref_logits_pos0.bin")
print(f"  shape={ref_pos0.shape}, range=[{ref_pos0.min():.6f}, {ref_pos0.max():.6f}], mean={ref_pos0.mean():.6f}")

print("\n=== Reference Position 1 Logits ===")
ref_pos1 = load_bin(f"{ref_dir}\\ref_logits_pos1.bin")
print(f"  shape={ref_pos1.shape}, range=[{ref_pos1.min():.6f}, {ref_pos1.max():.6f}], mean={ref_pos1.mean():.6f}")

# Compare reference pos0 vs pos1 logits
diff = ref_pos0 - ref_pos1
print(f"\nRef pos0 vs pos1 logits: max_diff={np.abs(diff).max():.6f}, rmse={np.sqrt(np.mean(diff*diff)):.6f}, cos_sim={np.dot(ref_pos0, ref_pos1)/(np.linalg.norm(ref_pos0)*np.linalg.norm(ref_pos1)):.10f}")

# Native position 1 logits (op_299)
native_pos1 = load_bin(f"{native_dir}\\op_299.bin")
print(f"\nNative pos1 logits: shape={native_pos1.shape}, range=[{native_pos1.min():.6f}, {native_pos1.max():.6f}], mean={native_pos1.mean():.6f}")

# Native pos0 logits (need to re-run or check if saved)
# For now, compare native pos1 with ref pos1
diff = native_pos1 - ref_pos1
print(f"\nNative pos1 vs Ref pos1: max_diff={np.abs(diff).max():.6f}, rmse={np.sqrt(np.mean(diff*diff)):.6f}, cos_sim={np.dot(native_pos1, ref_pos1)/(np.linalg.norm(native_pos1)*np.linalg.norm(ref_pos1)):.10f}")

# Check if native pos1 matches native pos0 from earlier run
# Load old native pos0 from single token run
old_native_pos0 = load_bin(r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\parity_ir\op_299.bin')
print(f"\nOld native pos0 (single token): shape={old_native_pos0.shape}, range=[{old_native_pos0.min():.6f}, {old_native_pos0.max():.6f}], mean={old_native_pos0.mean():.6f}")

diff = old_native_pos0 - ref_pos0
print(f"Old native pos0 vs Ref pos0: max_diff={np.abs(diff).max():.6f}, rmse={np.sqrt(np.mean(diff*diff)):.6f}, cos_sim={np.dot(old_native_pos0, ref_pos0)/(np.linalg.norm(old_native_pos0)*np.linalg.norm(ref_pos0)):.10f}")