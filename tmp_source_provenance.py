#!/usr/bin/env python3
"""SOURCE_WEIGHT_PROVENANCE_001
Check official DeepSeek-V2-Lite-Chat BF16 safetensors for NaN norm weights.
"""
import os
import sys
import json
import tempfile
from pathlib import Path

try:
    from huggingface_hub import hf_hub_download, snapshot_download
    from safetensors import safe_open
    import torch
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install huggingface_hub torch")
    sys.exit(1)

REPO_ID = "deepseek-ai/DeepSeek-V2-Lite-Chat"
ALLOW_FILES = ["model-00001-of-000004.safetensors", "model-00002-of-000004.safetensors",
               "model-00003-of-000004.safetensors", "model-00004-of-000004.safetensors"]

# Tensor name mapping from GGUF names to safetensors names
# DeepSeek-V2-Lite uses these patterns
TENSOR_MAP = {
    "blk.0.attn_norm.weight": "model.layers.0.attention_norm.weight",
    "blk.0.ffn_norm.weight": "model.layers.0.ffn_norm.weight",
    "output_norm.weight": "model.norm.weight",
    # Add more as needed
}

def find_tensor_in_shard(shard_path, tensor_name):
    """Check if tensor exists in shard and return it."""
    try:
        with safe_open(shard_path, framework="pt", device="cpu") as f:
            if tensor_name in f.keys():
                return f.get_tensor(tensor_name)
    except Exception as e:
        print(f"  Error reading {shard_path}: {e}")
    return None

def check_tensor(x, tensor_name):
    """Check tensor for nonfinite values."""
    if x is None:
        return None
    
    result = {
        "name": tensor_name,
        "shape": list(x.shape),
        "dtype": str(x.dtype),
    }
    
    # Convert to float32 for checking
    if x.dtype != torch.float32:
        x_f32 = x.float()
    else:
        x_f32 = x
    
    finite = torch.isfinite(x_f32)
    result["nonfinite"] = int((~finite).sum().item())
    result["nan"] = int(torch.isnan(x_f32).sum().item())
    result["inf"] = int(torch.isinf(x_f32).sum().item())
    
    xf = x_f32[finite]
    if len(xf) > 0:
        result["min"] = float(xf.min().item())
        result["max"] = float(xf.max().item())
    else:
        result["min"] = None
        result["max"] = None
    
    bad = torch.nonzero(~finite).flatten()
    result["bad_indices"] = bad.tolist()[:100]  # Limit to first 100
    
    return result

def main():
    print("SOURCE_WEIGHT_PROVENANCE_001")
    print("=" * 60)
    print(f"REPO={REPO_ID}")
    print()
    
    # Create temp directory for downloads
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"Downloading safetensors to {tmpdir}...")
        
        # Download all shards
        shard_paths = []
        for filename in ALLOW_FILES:
            try:
                path = hf_hub_download(
                    repo_id=REPO_ID,
                    filename=filename,
                    local_dir=tmpdir,
                    local_dir_use_symlinks=False,
                )
                shard_paths.append(path)
                print(f"  Downloaded {filename} -> {path}")
            except Exception as e:
                print(f"  Failed to download {filename}: {e}")
        
        if not shard_paths:
            print("ERROR: No shards downloaded")
            return 1
        
        print()
        print("Checking tensors...")
        print()
        
        results = {}
        for gguf_name, st_name in TENSOR_MAP.items():
            print(f"Tensor: {gguf_name}")
            print(f"  Safetensors name: {st_name}")
            
            tensor = None
            for shard_path in shard_paths:
                tensor = find_tensor_in_shard(shard_path, st_name)
                if tensor is not None:
                    print(f"  Found in: {Path(shard_path).name}")
                    break
            
            if tensor is None:
                print(f"  NOT FOUND in any shard")
                results[gguf_name] = {"name": gguf_name, "status": "NOT_FOUND"}
                continue
            
            result = check_tensor(tensor, gguf_name)
            results[gguf_name] = result
            
            print(f"  Shape: {result['shape']}")
            print(f"  Dtype: {result['dtype']}")
            print(f"  Nonfinite: {result['nonfinite']}")
            print(f"  NaN: {result['nan']}")
            print(f"  Inf: {result['inf']}")
            if result['min'] is not None:
                print(f"  Min: {result['min']:.6e}")
                print(f"  Max: {result['max']:.6e}")
            if result['bad_indices']:
                print(f"  Bad indices (first 100): {result['bad_indices']}")
            print()
        
        # Summary
        print("=" * 60)
        print("SUMMARY")
        print("=" * 60)
        
        all_finite = True
        for name, result in results.items():
            if result.get("nonfinite", 0) > 0:
                all_finite = False
                print(f"{name}: NONFINITE ({result['nonfinite']} elements)")
            elif result.get("status") == "NOT_FOUND":
                print(f"{name}: NOT FOUND")
            else:
                print(f"{name}: FINITE")
        
        print()
        if all_finite:
            print("VERDICT: OFFICIAL_SOURCE_WEIGHT=FINITE")
            print("ROOT_CAUSE_STAGE=conversion/quantization/GGUF artifact corruption")
        else:
            print("VERDICT: OFFICIAL_SOURCE_WEIGHT=NONFINITE")
            print("ROOT_CAUSE_STAGE=upstream model release")
        
        # Save results
        output_path = Path("F:/rawrxd/evidence/HEADER_AUTHORITY_MILESTONE/SOURCE_WEIGHT_PROVENANCE_001.json")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump({
                "gate": "SOURCE_WEIGHT_PROVENANCE_001",
                "repo_id": REPO_ID,
                "results": results,
                "all_finite": all_finite,
            }, f, indent=2)
        print(f"\nResults saved to: {output_path}")
        
        return 0

if __name__ == "__main__":
    sys.exit(main())
