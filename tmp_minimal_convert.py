#!/usr/bin/env python3
"""Minimal DeepSeek-V2-Lite GGUF converter using gguf-py directly."""
import sys
import json
import struct
from pathlib import Path
import numpy as np

try:
    from gguf import gguf_writer, constants, tensor_mapping
except ImportError as e:
    print(f"Missing dependency: {e}")
    sys.exit(1)

SAFETENSORS_DIR = Path("F:/rawrxd/tmp_safetensors")
OUTPUT_PATH = Path("F:/rawrxd/tmp_clean_bf16.gguf")

# DeepSeek-V2 tensor name mapping: safetensors -> GGUF
TENSOR_MAP = {
    "model.embed_tokens.weight": "token_embd.weight",
    "model.norm.weight": "output_norm.weight",
    # Layer norm tensors
    "model.layers.{}.input_layernorm.weight": "blk.{}.attn_norm.weight",
    "model.layers.{}.post_attention_layernorm.weight": "blk.{}.ffn_norm.weight",
    "model.layers.{}.self_attn.kv_a_layernorm.weight": "blk.{}.attn_kv_a_norm.weight",
    # Attention tensors
    "model.layers.{}.self_attn.q_proj.weight": "blk.{}.attn_q.weight",
    "model.layers.{}.self_attn.kv_a_proj_with_mqa.weight": "blk.{}.attn_kv_a_mqa.weight",
    "model.layers.{}.self_attn.kv_b_proj.weight": "blk.{}.attn_kv_b.weight",
    "model.layers.{}.self_attn.v_b_proj.weight": "blk.{}.attn_v_b.weight",
    "model.layers.{}.self_attn.o_proj.weight": "blk.{}.attn_output.weight",
    # MoE FFN tensors
    "model.layers.{}.mlp.gate_proj.weight": "blk.{}.ffn_gate.weight",
    "model.layers.{}.mlp.up_proj.weight": "blk.{}.ffn_up.weight",
    "model.layers.{}.mlp.down_proj.weight": "blk.{}.ffn_down.weight",
    "model.layers.{}.mlp.gate.weight": "blk.{}.ffn_gate_inp.weight",
    "model.layers.{}.mlp.experts.down_proj.weight": "blk.{}.ffn_down_exps.weight",
    "model.layers.{}.mlp.experts.gate_proj.weight": "blk.{}.ffn_gate_exps.weight",
    "model.layers.{}.mlp.experts.up_proj.weight": "blk.{}.ffn_up_exps.weight",
    "model.layers.{}.mlp.shared_experts.down_proj.weight": "blk.{}.ffn_down_shexp.weight",
    "model.layers.{}.mlp.shared_experts.gate_proj.weight": "blk.{}.ffn_gate_shexp.weight",
    "model.layers.{}.mlp.shared_experts.up_proj.weight": "blk.{}.ffn_up_shexp.weight",
}

def get_gguf_name(safetensors_name):
    """Convert safetensors name to GGUF name."""
    # Check direct mappings first
    if safetensors_name in TENSOR_MAP:
        return TENSOR_MAP[safetensors_name]
    
    # Check pattern mappings with layer index
    for st_pattern, gguf_pattern in TENSOR_MAP.items():
        if "{}" in st_pattern:
            # Try to match pattern
            parts = st_pattern.split("{}")
            if len(parts) == 2 and safetensors_name.startswith(parts[0]):
                rest = safetensors_name[len(parts[0]):]
                if rest.endswith(parts[1]):
                    idx = rest[:-len(parts[1])]
                    if idx.isdigit():
                        return gguf_pattern.format(idx)
    
    return None

def main():
    print("Minimal DeepSeek-V2-Lite GGUF Converter")
    print("=" * 60)
    
    # Load config
    config_path = SAFETENSORS_DIR / "config.json"
    if not config_path.exists():
        print(f"ERROR: {config_path} not found")
        return 1
    
    with open(config_path) as f:
        config = json.load(f)
    
    print(f"Model type: {config.get('model_type', 'unknown')}")
    print(f"Architecture: {config.get('architectures', ['unknown'])[0]}")
    
    # Count layers
    num_layers = config.get("num_hidden_layers", 0)
    hidden_size = config.get("hidden_size", 0)
    vocab_size = config.get("vocab_size", 0)
    print(f"Layers: {num_layers}, Hidden: {hidden_size}, Vocab: {vocab_size}")
    
    # Create GGUF writer
    writer = gguf_writer.GGUFWriter(str(OUTPUT_PATH), "temp", endianess=constants.GGUFEndian.LITTLE)
    
    # Add metadata
    writer.add_architecture(constants.MODEL_ARCH.DEEPSEEK2)
    writer.add_codeset("BPE")
    writer.add_context_length(config.get("max_position_embeddings", 4096))
    writer.add_embedding_length(hidden_size)
    writer.add_block_count(num_layers)
    writer.add_feed_forward_length(config.get("intermediate_size", 0))
    writer.add_rope_freq_base(config.get("rope_theta", 10000.0))
    
    # Add quantization info
    writer.add_quantization_version(constants.GGML_QUANT_VERSION)
    
    print("\nConverting tensors...")
    
    # Process all safetensors shards
    tensor_count = 0
    for shard_path in sorted(SAFETENSORS_DIR.glob("model-*-of-*.safetensors")):
        print(f"  Processing {shard_path.name}...")
        
        try:
            from safetensors import safe_open
            with safe_open(str(shard_path), framework="pt", device="cpu") as f:
                keys = f.keys()
                for key in keys:
                    gguf_name = get_gguf_name(key)
                    if gguf_name is None:
                        print(f"    WARNING: No mapping for {key}")
                        continue
                    
                    tensor = f.get_tensor(key)
                    data = tensor.numpy()
                    
                    # Determine GGUF type
                    if data.dtype == np.float32:
                        ggml_type = constants.GGMLQuantizationType.F32
                    elif data.dtype == np.float16:
                        ggml_type = constants.GGMLQuantizationType.F16
                    elif data.dtype == np.uint8:
                        ggml_type = constants.GGMLQuantizationType.Q8_0
                    else:
                        print(f"    WARNING: Unsupported dtype {data.dtype} for {key}")
                        continue
                    
                    # Add tensor info
                    writer.add_tensor_info(
                        gguf_name,
                        ggml_type,
                        data.shape,
                        data.tobytes(),
                    )
                    tensor_count += 1
                    
        except Exception as e:
            print(f"    ERROR processing {shard_path}: {e}")
            continue
    
    print(f"\nTotal tensors: {tensor_count}")
    
    # Write file
    print(f"\nWriting {OUTPUT_PATH}...")
    writer.write_header()
    writer.write_kv_data()
    writer.write_tensor_data()
    
    writer.close()
    
    if OUTPUT_PATH.exists():
        size_gb = OUTPUT_PATH.stat().st_size / 1024 / 1024 / 1024
        print(f"SUCCESS: Created {OUTPUT_PATH} ({size_gb:.2f} GB)")
        return 0
    else:
        print("ERROR: Output file not created")
        return 1

if __name__ == "__main__":
    sys.exit(main())
