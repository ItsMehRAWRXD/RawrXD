#!/usr/bin/env python3
"""ABI Verifier for llama.cpp Python ctypes bridge
Compares Python ctypes structure sizes/offsets with expected native values."""

import ctypes
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

# Import the bridge structures
from backend.rawrxd_agent_bridge import (
    llama_model_params,
    llama_context_params,
    llama_batch,
    llama_split_mode,
    llama_load_mode,
    llama_lazy_mode,
    llama_context_type,
    llama_rope_scaling_type,
    llama_pooling_type,
    llama_attention_type,
    llama_flash_attn_type,
    ggml_type,
)

def print_struct_info(name, struct_cls):
    """Print size and field offsets for a ctypes Structure."""
    print(f"--- {name} ---")
    print(f"sizeof({name}) = {ctypes.sizeof(struct_cls)}")
    dummy = struct_cls()
    base_addr = ctypes.addressof(dummy)
    for field_name, field_type in struct_cls._fields_:
        try:
            field_obj = getattr(dummy, field_name)
            offset = ctypes.addressof(field_obj) - base_addr
            print(f"offsetof({name}, {field_name}) = {offset}")
        except (TypeError, ValueError):
            # Some field types (like unions, arrays, complex types) may not support addressof
            print(f"offsetof({name}, {field_name}) = <unavailable>")

def print_enum_info(name, enum_cls):
    """Print size of enum."""
    print(f"sizeof({name}) = {ctypes.sizeof(enum_cls)}")

def main():
    print("=== LLAMA STRUCT ABI VERIFICATION (Python ctypes) ===\n")

    # Structures
    print_struct_info("llama_model_params", llama_model_params)
    print()
    print_struct_info("llama_context_params", llama_context_params)
    print()
    print_struct_info("llama_batch", llama_batch)
    print()

    # Enums
    print("--- Enum sizes ---")
    print_enum_info("llama_split_mode", llama_split_mode)
    print_enum_info("llama_load_mode", llama_load_mode)
    print_enum_info("llama_lazy_mode", llama_lazy_mode)
    print_enum_info("llama_context_type", llama_context_type)
    print_enum_info("llama_rope_scaling_type", llama_rope_scaling_type)
    print_enum_info("llama_pooling_type", llama_pooling_type)
    print_enum_info("llama_attention_type", llama_attention_type)
    print_enum_info("llama_flash_attn_type", llama_flash_attn_type)
    print_enum_info("ggml_type", ggml_type)
    print()

    # Pointer sizes
    print("--- Pointer sizes ---")
    print(f"sizeof(void*) = {ctypes.sizeof(ctypes.c_void_p)}")
    print(f"sizeof(ctypes.POINTER(llama_model)) = {ctypes.sizeof(ctypes.POINTER(ctypes.c_void_p))}")  # opaque
    print(f"sizeof(ctypes.POINTER(llama_context)) = {ctypes.sizeof(ctypes.POINTER(ctypes.c_void_p))}")  # opaque
    print(f"sizeof(ctypes.POINTER(llama_sampler)) = {ctypes.sizeof(ctypes.POINTER(ctypes.c_void_p))}")  # opaque
    print(f"sizeof(ctypes.POINTER(ggml_backend_dev)) = {ctypes.sizeof(ctypes.POINTER(ctypes.c_void_p))}")  # opaque

if __name__ == "__main__":
    main()