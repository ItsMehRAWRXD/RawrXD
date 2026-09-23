import os
import gguf

SRC_PATH = r"F:\~dev\rawrxd\src\core\test_tiny.gguf"
VOCAB_SRC = r"F:\~dev\rawrxd\src\core\test_minimal.gguf"
DST_PATH = r"F:\~dev\rawrxd\src\core\test_tiny_with_vocab.gguf"

def _copy_field(writer, key, field):
    if not field.types:
        return
    main_type = field.types[0]
    try:
        if main_type == gguf.GGUFValueType.ARRAY:
            sub_type = field.types[-1]
            contents = field.contents()
            if sub_type == gguf.GGUFValueType.STRING:
                writer.add_array(key, contents)
            elif sub_type == gguf.GGUFValueType.INT32:
                writer.add_array(key, [int(v) for v in contents])
            elif sub_type == gguf.GGUFValueType.FLOAT32:
                writer.add_array(key, [float(v) for v in contents])
            elif sub_type == gguf.GGUFValueType.UINT32:
                writer.add_array(key, [int(v) for v in contents])
            else:
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
    except Exception as e:
        print(f"Warning: failed to copy {key}: {e}")


src = gguf.GGUFReader(SRC_PATH, 'r')
vocab = gguf.GGUFReader(VOCAB_SRC, 'r')

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

# Copy tensors - use t.data and do NOT pass raw_shape
for t in src.tensors:
    writer.add_tensor(t.name, t.data, raw_dtype=t.tensor_type)

writer.write_header_to_file()
writer.write_kv_data_to_file()
writer.write_tensors_to_file()
writer.close()

print(f"Wrote {len(src.tensors)} tensors + tokenizer metadata to {DST_PATH}")

# Verify
r = gguf.GGUFReader(DST_PATH)
for t in r.tensors:
    if 'ffn' in t.name:
        print(f'{t.name}: shape={list(t.shape)}, data_shape={list(t.data.shape)}')

def _copy_field(writer, key, field):
    if not field.types:
        return
    main_type = field.types[0]
    try:
        if main_type == gguf.GGUFValueType.ARRAY:
            sub_type = field.types[-1]
            contents = field.contents()
            if sub_type == gguf.GGUFValueType.STRING:
                writer.add_array(key, contents)
            elif sub_type == gguf.GGUFValueType.INT32:
                writer.add_array(key, [int(v) for v in contents])
            elif sub_type == gguf.GGUFValueType.FLOAT32:
                writer.add_array(key, [float(v) for v in contents])
            elif sub_type == gguf.GGUFValueType.UINT32:
                writer.add_array(key, [int(v) for v in contents])
            else:
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
    except Exception as e:
        print(f"Warning: failed to copy {key}: {e}")
