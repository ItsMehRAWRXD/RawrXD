import numpy as np
import struct
import json
import os

def load_bin(path, expected_count=None):
    with open(path, 'rb') as f:
        data = f.read()
    if expected_count and len(data) != expected_count * 4:
        raise ValueError(f"Expected {expected_count*4} bytes, got {len(data)}")
    arr = np.frombuffer(data, dtype=np.float32)
    return arr

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

def compare_records(native_dir, ref_path, pos):
    # Load reference logits
    ref = load_bin(os.path.join(ref_dir, f'ref_logits_pos{pos}.bin'))
    
    # Load manifest
    native_manifest = load_manifest(os.path.join(native_dir, 'manifest.json'))
    
    # Find all records for this position
    pos_records = [r for r in native_manifest if r['position'] == pos]
    
    print(f"=== Position {pos} Analysis ===")
    print(f"Native records at pos {pos}: {len(pos_records)}")
    
    # Group by tensor type
    by_type = {}
    for r in pos_records:
        t = r['tensor_type']
        if t not in by_type:
            by_type[t] = []
        by_type[t].append(r)
    
    print(f"Tensor types at pos {pos}: {list(by_type.keys())}")
    
    # Compare reference logits with native logits
    # Find logits record
    logits_records = [r for r in pos_records if r['tensor_type'] == 'output' and r['op_id'] == 299]
    if logits_records:
        native_logits_path = os.path.join(native_dir, f"rec_{logits_records[0]['index']:06d}_op{logits_records[0]['op_id']}_Output_l4294967295_p{pos}_output.bin")
        if os.path.exists(native_logits_path):
            native_logits = load_binary_record(native_logits_path, None)[0]
            ref_logits = load_bin(os.path.join(ref_dir, f'ref_logits_pos{pos}.bin'))
            
            print(f"\n=== Position {pos} Logits Comparison ===")
            print(f"Native shape: {native_logits.shape}, Ref shape: {ref_logits.shape}")
            native_argmax = int(native_logits.argmax())
            ref_argmax = int(ref_logits.argmax())
            print(f"Native argmax: {native_argmax} (logit={native_logits[native_argmax]:.6f})")
            print(f"Ref argmax:    {ref_argmax} (logit={ref_logits[ref_argmax]:.6f})")
            print(f"Argmax match: {native_argmax == ref_argmax}")
            
            diff = native_logits - ref_logits
            abs_diff = np.abs(diff)
            max_abs_diff = abs_diff.max()
            rmse = np.sqrt(np.mean(diff * diff))
            dot = np.dot(native_logits, ref_logits)
            norm_n = np.linalg.norm(native_logits)
            norm_r = np.linalg.norm(ref_logits)
            cos_sim = dot / (norm_n * norm_r) if norm_n > 0 and norm_r > 0 else 0
            
            print(f"Max abs diff: {max_abs_diff:.6f} at {abs_diff.argmax()}")
            print(f"RMSE: {rmse:.6f}")
            print(f"Cosine: {cos_sim:.10f}")
            
            # Top-10
            native_top10 = np.argpartition(native_logits, -10)[-10:]
            native_top10 = native_top10[np.argsort(native_logits[native_top10])[::-1]]
            ref_top10 = np.argpartition(ref_logits, -10)[-10:]
            ref_top10 = ref_top10[np.argsort(ref_logits[ref_top10])[::-1]]
            print(f"Native top-10: {native_top10.tolist()}")
            print(f"Ref top-10:    {ref_top10.tolist()}")
            print(f"Top-10 overlap: {len(set(native_top10) & set(ref_top10))}/10")
            
            # Margins
            print(f"\nMargins (185 - 1): native={native_logits[185]-native_logits[1]:.6f}, ref={ref_logits[185]-ref_logits[1]:.6f}")
            
            # Find first significant divergence in intermediate tensors
            print(f"\n=== Layer-by-layer comparison (first few layers) ===")
            for layer in range(3):  # Check first 3 layers
                print(f"\n  Layer {layer}:")
                # Check MLA Decompress
                mla_in = [r for r in pos_records if r['layer_idx'] == layer and r['tensor_type'] == 'input' and 'MlaDecompress' in r['op_name']]
                if mla_in:
                    r = mla_in[0]
                    native_path = os.path.join(native_dir, f"rec_{r['index']:06d}_op{r['op_id']}_{r['op_name']}_l{r['layer_idx']}_p{r['position']}_{r['tensor_type']}.bin")
                    if os.path.exists(native_path):
                        data = load_binary_record(native_path, None)[0]
                        print(f"  MlaDecompress_Input: shape={data.shape}, range=[{data.min():.4f}, {data.max():.4f}], norm={np.linalg.norm(data):.4f}")
                
                # Check Attention scores
                scores = [r for r in pos_records if r['layer_idx'] == layer and r['tensor_type'] == 'scaled_scores']
                if scores:
                    r = scores[0]
                    native_path = os.path.join(native_dir, f"rec_{r['index']:06d}_op{r['op_id']}_{r['op_name']}_l{r['layer_idx']}_p{r['position']}_{r['tensor_type']}.bin")
                    if os.path.exists(native_path):
                        data = load_binary_record(native_path, None)[0]
                        print(f"  Attention_Scores: shape={data.shape}, range=[{data.min():.4f}, {data.max():.4f}], norm={np.linalg.norm(data):.4f}")
                
                # Check Attention weights
                weights = [r for r in pos_records if r['layer_idx'] == layer and r['tensor_type'] == 'softmax']
                if weights:
                    r = weights[0]
                    native_path = os.path.join(native_dir, f"rec_{r['index']:06d}_op{r['op_id']}_{r['op_name']}_l{r['layer_idx']}_p{r['position']}_{r['tensor_type']}.bin")
                    if os.path.exists(native_path):
                        data = load_binary_record(native_path, None)[0]
                        print(f"  Attention_Weights: shape={data.shape}, range=[{data.min():.4f}, {data.max():.4f}], norm={np.linalg.norm(data):.4f}")
                
                # Check Attention output
                attn_out = [r for r in pos_records if r['layer_idx'] == layer and r['tensor_type'] == 'output' and 'Attention' in r['op_name']]
                if attn_out:
                    r = attn_out[0]
                    native_path = os.path.join(native_dir, f"rec_{r['index']:06d}_op{r['op_id']}_{r['op_name']}_l{r['layer_idx']}_p{r['position']}_{r['tensor_type']}.bin")
                    if os.path.exists(native_path):
                        data = load_binary_record(native_path, None)[0]
                        print(f"  Attention_Output: shape={data.shape}, range=[{data.min():.4f}, {data.max():.4f}], norm={np.linalg.norm(data):.4f}")

if __name__ == '__main__':
    native_dir = r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\pos2_capture_fixed'
    ref_dir = r'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001'
    
    compare_records(native_dir, os.path.join(ref_dir, 'ref_logits_pos2.bin'), 2)