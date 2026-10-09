import json
import struct
import numpy as np
import os

def load_manifest(manifest_path):
    with open(manifest_path, 'r') as f:
        return json.load(f)

def load_binary_record(record_path, manifest_entry):
    with open(record_path, 'rb') as f:
        # Read header
        op_id = struct.unpack('I', f.read(4))[0]
        layer_idx = struct.unpack('I', f.read(4))[0]
        position = struct.unpack('Q', f.read(8))[0]
        ndim = struct.unpack('I', f.read(4))[0]
        shape = []
        for _ in range(ndim):
            shape.append(struct.unpack('q', f.read(8))[0])
        data_size = struct.unpack('Q', f.read(8))[0]
        data = np.frombuffer(f.read(data_size * 4), dtype=np.float32)
    return data, shape

def compare_records(native_dir, ref_dir):
    native_manifest = os.path.join(native_dir, 'manifest.json')
    ref_manifest = os.path.join(ref_dir, 'manifest.json')
    
    if not os.path.exists(native_manifest):
        print(f"Native manifest not found: {native_manifest}")
        return
    if not os.path.exists(ref_manifest):
        print(f"Reference manifest not found: {ref_manifest}")
        return
    
    with open(native_manifest, 'r') as f:
        native_manifest_data = json.load(f)
    with open(ref_manifest, 'r') as f:
        ref_manifest_data = json.load(f)
    
    # Build lookup by op_name, layer, position, tensor_type
    native_lookup = {}
    for entry in native_manifest_data:
        key = (entry['op_name'], entry['layer_idx'], entry['position'], entry['tensor_type'])
        native_lookup[key] = entry
    
    ref_lookup = {}
    for entry in ref_manifest_data:
        key = (entry['op_name'], entry['layer_idx'], entry['position'], entry['tensor_type'])
        ref_lookup[key] = entry
    
    # Compare matching records
    all_keys = set(native_lookup.keys()) | set(ref_lookup.keys())
    
    print(f"Native records: {len(native_lookup)}")
    print(f"Reference records: {len(ref_lookup)}")
    print(f"Common keys: {len(set(native_lookup.keys()) & set(ref_lookup.keys()))}")
    print(f"Native only: {len(set(native_lookup.keys()) - set(ref_lookup.keys()))}")
    print(f"Ref only: {len(set(ref_lookup.keys()) - set(native_lookup.keys()))}")
    
    divergences = []
    
    for key in sorted(set(native_lookup.keys()) & set(ref_lookup.keys())):
        native_entry = native_lookup[key]
        ref_entry = ref_lookup[key]
        
        native_path = os.path.join(native_dir, f"rec_{native_entry['op_name']}_l{native_entry['layer_idx']}_p{native_entry['position']}_{native_entry['tensor_type']}.bin")
        ref_path = os.path.join(ref_dir, f"rec_{ref_entry['op_name']}_l{ref_entry['layer_idx']}_p{ref_entry['position']}_{ref_entry['tensor_type']}.bin")
        
        if not os.path.exists(native_path) or not os.path.exists(ref_path):
            continue
            
        native_data, native_shape = load_binary_record(os.path.join(native_dir, os.path.basename(native_path)), native_entry)
        ref_data, ref_shape = load_binary_record(os.path.join(ref_dir, os.path.basename(ref_path)), ref_entry)
        
        if native_data.shape != ref_data.shape:
            print(f"  SHAPE MISMATCH {key}: native={native_data.shape}, ref={ref_data.shape}")
            continue
        
        diff = native_data - ref_data
        abs_diff = np.abs(diff)
        max_abs = abs_diff.max()
        rmse = np.sqrt(np.mean(diff * diff))
        mean_abs = abs_diff.mean()
        
        dot = np.dot(native_data, ref_data)
        norm_n = np.linalg.norm(native_data)
        norm_r = np.linalg.norm(ref_data)
        cos_sim = dot / (norm_n * norm_r) if norm_n > 0 and norm_r > 0 else 0
        
        if max_abs > 1e-3 or rmse > 1e-3:
            divergences.append({
                'key': key,
                'max_abs': float(max_abs),
                'rmse': float(rmse),
                'mean_abs': float(mean_abs),
                'cos_sim': float(cos_sim),
                'shape': native_data.shape
            })
    
    # Sort by RMSE descending
    divergences.sort(key=lambda x: x['rmse'], reverse=True)
    
    print(f"\n=== Top Divergences ===")
    for d in divergences[:20]:
        print(f"  {d['key']}: shape={d['shape']}, max_abs={d['max_abs']:.6f}, rmse={d['rmse']:.6f}, mean_abs={d['mean_abs']:.6f}, cos_sim={d['cos_sim']:.10f}")
    
    # Summary
    if divergences:
        print(f"\nTotal divergent tensors: {len(divergences)}")
        max_rmse = max(d['rmse'] for d in divergences)
        max_maxabs = max(d['max_abs'] for d in divergences)
        print(f"Max RMSE: {max_rmse:.6f}")
        print(f"Max absolute diff: {max_maxabs:.6f}")
    else:
        print("\nNo significant divergences found!")

if __name__ == '__main__':
    native_dir = r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\differential'
    ref_dir = r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\reference_differential'
    
    compare_records(native_dir, ref_dir)