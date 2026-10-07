#!/usr/bin/env python3
"""SOURCE_WEIGHT_PROVENANCE_001
Check official DeepSeek-V2-Lite-Chat BF16 safetensors for NaN norm weights.
"""
import sys
import json
from pathlib import Path

try:
    from safetensors import safe_open
    import torch
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install safetensors torch")
    sys.exit(1)

SHARD_PATH = Path("F:/rawrxd/tmp_model-00001-of-000004.safetensors")

# Tensor name mapping from GGUF names to safetensors names
TENSOR_MAP = {
    "blk.0.attn_norm.weight": "model.layers.0.input_layernorm.weight",
    "blk.0.ffn_norm.weight": "model.layers.0.post_attention_layernorm.weight",
    "output_norm.weight": "model.norm.weight",
}

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
    print(f"SOURCE=official DeepSeek-V2-Lite-Chat safetensors")
    print(f"SHARD={SHARD_PATH}")
    print()
    
    if not SHARD_PATH.exists():
        print(f"ERROR: Shard not found at {SHARD_PATH}")
        return 1
    
    print(f"Shard size: {SHARD_PATH.stat().st_size / 1024 / 1024 / 1024:.2f} GB")
    print()
    
    results = {}
    for gguf_name, st_name in TENSOR_MAP.items():
        print(f"Checking: {gguf_name}")
        print(f"  Safetensors name: {st_name}")
        
        try:
            with safe_open(str(SHARD_PATH), framework="pt", device="cpu") as f:
                if st_name not in f.keys():
                    print(f"  NOT FOUND in shard")
                    results[gguf_name] = {"name": gguf_name, "status": "NOT_FOUND"}
                    continue
                
                tensor = f.get_tensor(st_name)
                print(f"  Loaded: shape={tuple(tensor.shape)}, dtype={tensor.dtype}")
        except Exception as e:
            print(f"  ERROR loading tensor: {e}")
            results[gguf_name] = {"name": gguf_name, "status": "ERROR", "error": str(e)}
            continue
        
        result = check_tensor(tensor, gguf_name)
        results[gguf_name] = result
        
        print(f"  Nonfinite: {result['nonfinite']}")
        print(f"  NaN: {result['nan']}")
        print(f"  Inf: {result['inf']}")
        if result['min'] is not None:
            print(f"  Min: {result['min']:.6e}")
            print(f"  Max: {result['max']:.6e}")
        if result.get('bad_indices'):
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
        elif result.get("status") == "ERROR":
            print(f"{name}: ERROR - {result.get('error')}")
        else:
            print(f"{name}: FINITE")
    
    print()
    if all_finite:
        print("VERDICT: OFFICIAL_SOURCE_WEIGHT=FINITE")
        print("ROOT_CAUSE_STAGE=conversion/quantization/GGUF artifact corruption")
        print("NEXT=Option B: regenerate clean GGUF from official source")
    else:
        print("VERDICT: OFFICIAL_SOURCE_WEIGHT=NONFINITE")
        print("ROOT_CAUSE_STAGE=upstream model release")
        print("NEXT=Verify safetensors hash and investigate source model")
    
    # Save results
    output_path = Path("F:/rawrxd/evidence/HEADER_AUTHORITY_MILESTONE/SOURCE_WEIGHT_PROVENANCE_001.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({
            "gate": "SOURCE_WEIGHT_PROVENANCE_001",
            "source": "official DeepSeek-V2-Lite-Chat safetensors",
            "shard": str(SHARD_PATH),
            "results": results,
            "all_finite": all_finite,
        }, f, indent=2)
    print(f"\nResults saved to: {output_path}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
