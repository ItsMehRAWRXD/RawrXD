#!/usr/bin/env python3
"""
combine_tiny_with_vocab.py

Reads test_tiny.gguf (has transformer weights but no tokenizer metadata)
and test_minimal.gguf (has tokenizer metadata but minimal weights),
writes a new GGUF with:
- all tensors and metadata from test_tiny.gguf
- tokenizer metadata (tokenizer.ggml.tokens etc.) from test_minimal.gguf
"""
import os
import sys
import numpy as np
import gguf

SRC_PATH = r"F:\~dev\rawrxd\src\core\test_tiny.gguf"
VOCAB_SRC = r"F:\~dev\rawrxd\src\core\test_minimal.gguf"
DST_PATH = r"F:\~dev\rawrxd\src\core\test_tiny_with_vocab.gguf"

def main():
    if not os.path.exists(SRC_PATH):
        print(f"Missing source: {SRC_PATH}")
        sys.exit(1)
    if not os.path.exists(VOCAB_SRC):
        print(f"Missing vocab source: {VOCAB_SRC}")
        sys.exit(1)

    src = gguf.GGUFReader(SRC_PATH, 'r')
    vocab = gguf.GGUFReader(VOCAB_SRC, 'r')

    # Determine architecture from source metadata
    arch = "llama"
    try:
        arch = src.fields['general.architecture'].contents()
    except Exception:
        pass

    writer = gguf.GGUFWriter(DST_PATH, arch)

    # Copy metadata from source
    for key, field in src.fields.items():
        if key.startswith("GGUF."):
            continue
        _copy_field(writer, key, field)

    # Copy tokenizer metadata from vocab source
    for key in vocab.fields:
        if key.startswith("tokenizer."):
            _copy_field(writer, key, vocab.fields[key])

    # Copy tensors from source (weights)
    for t in src.tensors:
        # t.data is a numpy array
        # t.tensor_type is GGMLQuantizationType
        # t.shape is ndarray of uint32
        shape = [int(s) for s in t.shape]
        writer.add_tensor(t.name, t.data, raw_shape=shape, raw_dtype=t.tensor_type)

    writer.write_header_to_file()
    writer.write_kv_data_to_file()
    writer.write_tensors_to_file()
    writer.close()
    print(f"Wrote {len(src.tensors)} tensors + tokenizer metadata to {DST_PATH}")
    print(f"File size: {os.path.getsize(DST_PATH)} bytes")

def _copy_field(writer, key, field):
    """Copy a single metadata field from GGUFReader to GGUFWriter."""
    if not field.types:
        return
    main_type = field.types[0]
    try:
        if main_type == gguf.GGUFValueType.ARRAY:
            sub_type = field.types[-1]
            contents = field.contents()
            if sub_type == gguf.GGUFValueType.STRING:
                # contents returns list of strings
                writer.add_array(key, contents)
            elif sub_type == gguf.GGUFValueType.INT32:
                writer.add_array(key, [int(v) for v in contents])
            elif sub_type == gguf.GGUFValueType.FLOAT32:
                writer.add_array(key, [float(v) for v in contents])
            elif sub_type == gguf.GGUFValueType.UINT32:
                writer.add_array(key, [int(v) for v in contents])
            else:
                # Fallback: convert to list of native Python values
                writer.add_array(key, list(contents))
        elif main_type == gguf.GGUFValueType.STRING:
            writer.add_string(key, field.contents())
        elif main_type == gguf.GGUFValueType.INT32:
            writer.add_int32(key, int(field.contents()))
        elif main_type == gguf.GGUFValueType.INT64:
            writer.add_int64(key, int(field.contents()))
        elif main_type == gguf.GGUFValueType.FLOAT32:
            writer.add_float32(key, float(field.contents()))
        elif main_type == gguf.GGUFValueType.FLOAT64:
            writer.add_float64(key, float(field.contents()))
        elif main_type == gguf.GGUFValueType.UINT32:
            writer.add_uint32(key, int(field.contents()))
        elif main_type == gguf.GGUFValueType.UINT64:
            writer.add_uint64(key, int(field.contents()))
        elif main_type == gguf.GGUFValueType.BOOL:
            writer.add_bool(key, bool(field.contents()))
        else:
            print(f"  WARNING: skipping metadata key '{key}' with unhandled type {main_type}")
    except Exception as e:
        print(f"  ERROR copying field '{key}': {e}")


if __name__ == "__main__":
    main()
