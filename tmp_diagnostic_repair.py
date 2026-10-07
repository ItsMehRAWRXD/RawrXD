#!/usr/bin/env python3
"""Create a diagnostic repaired GGUF by patching 13 NaN F32 norm weights
using actual BF16 source values from official DeepSeek-V2-Lite-Chat safetensors.

This is a DIAGNOSTIC ONLY lane, not a certified model.
"""
import sys
import struct
from pathlib import Path

try:
    from safetensors import safe_open
    import torch
    import numpy as np
except ImportError as e:
    print(f"Missing dependency: {e}")
    sys.exit(1)

# Paths
SAFETENSORS_DIR = Path("F:/rawrxd/tmp_safetensors")
CORRUPTED_GGUF = Path("G:/~dev/rawrxd/models/DeepSeek-V2-Lite-Chat.Q4_K_M.gguf")
DIAGNOSTIC_GGUF = Path("F:/rawrxd/evidence/HEADER_AUTHORITY_MILESTONE/DeepSeek-V2-Lite-Chat.Q4_K_M.DIAGNOSTIC_REPAIRED.gguf")

# Known bad indices from previous analysis
BAD_INDICES = {
    "blk.0.attn_norm.weight": [166, 202, 561, 742, 746, 1029, 1335, 1497, 1555, 1675, 1677, 1929, 1930],
    "blk.0.ffn_norm.weight": [],  # Will be populated dynamically
}

# Tensor mapping
TENSOR_MAP = {
    "blk.0.attn_norm.weight": "model.layers.0.input_layernorm.weight",
    "blk.0.ffn_norm.weight": "model.layers.0.post_attention_layernorm.weight",
}

# Tensor offsets from ModelGenie evidence (data-relative, need to add data_start)
# These are from the generated TensorROM.generated.hpp
TENSOR_OFFSETS = {
    "blk.0.attn_norm.weight": 289996800,  # dataOffset from TensorROM
    "blk.0.ffn_norm.weight": 290004992,  # dataOffset from TensorROM
}

# GGUF data start from evidence
GGUF_DATA_START = 3972000

def main():
    print("DIAGNOSTIC_REPAIRED_GGUF_001")
    print("=" * 60)
    print(f"CORRUPTED_GGUF={CORRUPTED_GGUF}")
    print(f"DIAGNOSTIC_GGUF={DIAGNOSTIC_GGUF}")
    print()
    
    # Step 1: Load official BF16 source values for known bad indices
    print("Step 1: Loading official BF16 source values for known bad indices...")
    source_values = {}
    
    # Known bad indices from previous analysis of corrupted GGUF
    KNOWN_BAD_INDICES = {
        "blk.0.attn_norm.weight": [166, 202, 561, 742, 746, 1029, 1335, 1497, 1555, 1675, 1677, 1929, 1930],
        "blk.0.ffn_norm.weight": [215, 243, 383, 415, 417, 558, 599, 617],  # From previous analysis
    }
    
    with safe_open(str(SAFETENSORS_DIR / "model-00001-of-000004.safetensors"), framework="pt", device="cpu") as f:
        for gguf_name, st_name in TENSOR_MAP.items():
            if st_name not in f.keys():
                print(f"  WARNING: {st_name} not found")
                continue
            
            tensor = f.get_tensor(st_name)
            x_f32 = tensor.float()
            
            # Use known bad indices
            bad_indices = KNOWN_BAD_INDICES.get(gguf_name, [])
            
            # Extract source values at bad indices
            values = {}
            for idx in bad_indices:
                if idx < len(x_f32):
                    values[idx] = float(x_f32[idx].item())
            
            source_values[gguf_name] = values
            print(f"  {gguf_name}: {len(values)} source values extracted for patching")
    
    if not source_values:
        print("ERROR: No source values found")
        return 1
    
    # Verify source values are finite
    for tensor_name, values in source_values.items():
        for idx, val in values.items():
            if not np.isfinite(val):
                print(f"  ERROR: Source value at {tensor_name}[{idx}] is nonfinite: {val}")
                return 1
    
    print("  All source values are finite [OK]")
    
    # Step 2: Create diagnostic GGUF by copying and patching
    print("\nStep 2: Creating diagnostic repaired GGUF...")
    print("  Copying corrupted GGUF...")
    
    # Copy the file
    import shutil
    shutil.copy2(CORRUPTED_GGUF, DIAGNOSTIC_GGUF)
    
    print("  Patching NaN values with official BF16 source values...")
    
    # Open the diagnostic GGUF for patching
    with open(DIAGNOSTIC_GGUF, "r+b") as f:
        for tensor_name, bad_indices in BAD_INDICES.items():
            if not bad_indices:
                continue
            
            if tensor_name not in TENSOR_OFFSETS:
                print(f"  WARNING: No offset for {tensor_name}")
                continue
            
            # Calculate absolute offset
            data_offset = TENSOR_OFFSETS[tensor_name]
            absolute_offset = GGUF_DATA_START + data_offset
            
            # Seek to tensor data
            f.seek(absolute_offset)
            
            # Read the entire tensor (2048 floats = 8192 bytes)
            tensor_data = f.read(8192)
            
            if len(tensor_data) != 8192:
                print(f"  ERROR: Expected 8192 bytes, got {len(tensor_data)}")
                continue
            
            # Unpack as float32 array
            import array
            floats = array.array('f', tensor_data)
            
            # Patch bad values using known indices
            patched = 0
            for idx in bad_indices:
                if idx < len(floats):
                    old_value = floats[idx]
                    if tensor_name in source_values and idx in source_values[tensor_name]:
                        new_value = source_values[tensor_name][idx]
                        floats[idx] = new_value
                        patched += 1
            
            # Write back
            f.seek(absolute_offset)
            f.write(floats.tobytes())
            
            print(f"  {tensor_name}: Patched {patched} values")
    
    print(f"\nDiagnostic GGUF created: {DIAGNOSTIC_GGUF}")
    print(f"Size: {DIAGNOSTIC_GGUF.stat().st_size / 1024 / 1024 / 1024:.2f} GB")
    
    # Step 3: Verify the patch
    print("\nStep 3: Verifying patch...")
    
    with open(DIAGNOSTIC_GGUF, "rb") as f:
        for tensor_name, bad_indices in BAD_INDICES.items():
            if not bad_indices or tensor_name not in TENSOR_OFFSETS:
                continue
            
            data_offset = TENSOR_OFFSETS[tensor_name]
            absolute_offset = GGUF_DATA_START + data_offset
            f.seek(absolute_offset)
            tensor_data = f.read(8192)
            floats = array.array('f', tensor_data)
            
            # Check if bad indices are now finite
            nonfinite = sum(1 for idx in bad_indices if idx < len(floats) and not np.isfinite(floats[idx]))
            print(f"  {tensor_name}: {nonfinite} nonfinite values remaining at bad indices")
    
    print("\nNOTE: This is a DIAGNOSTIC ONLY file.")
    print("      SOURCE_MODEL_MODIFIED=1")
    print("      DIAGNOSTIC_ONLY=1")
    print("      CERTIFIED_MODEL=0")
    print("      TOKEN_OUTPUT_CERTIFIABLE=0")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
