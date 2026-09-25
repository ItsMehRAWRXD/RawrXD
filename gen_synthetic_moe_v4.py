import struct
import io

def write_u32(f, v): f.write(struct.pack('<I', v))
def write_u64(f, v): f.write(struct.pack('<Q', v))
def write_i32(f, v): f.write(struct.pack('<i', v))
def write_f32(f, v): f.write(struct.pack('<f', v))
def write_str(f, s):
    b = s.encode('utf-8')
    write_u64(f, len(b))
    f.write(b)

# Model dims
V = 16
H = 64
I = 32
E = 4
n_layers = 2

tokens = ['<unk>'] + [f'token{i}' for i in range(1, V)]

f = io.BytesIO()

# Header (v2)
write_u32(f, 0x46554747)  # magic 'GGUF'
write_u32(f, 2)             # version 2
write_u64(f, 0)             # tensor count placeholder
write_u64(f, 0)             # metadata count placeholder

# Metadata (tightly packed, NO alignment between entries)
metadata = [
    ('general.architecture', 8, 'llama'),
    ('general.name', 8, 'synthetic_moe'),
    ('general.alignment', 4, 32),
    ('llama.block_count', 4, n_layers),
    ('llama.context_length', 4, 128),
    ('llama.embedding_length', 4, H),
    ('llama.feed_forward_length', 4, I),
    ('llama.attention.head_count', 4, 4),
    ('llama.attention.head_count_kv', 4, 4),
    ('llama.attention.layer_norm_rms_epsilon', 4, 0x3A4CCCCD),
    ('llama.expert_count', 4, E),
    ('llama.expert_used_count', 4, 2),
    ('llama.rope.dimension_count', 4, 64),
    ('llama.rope.freq_base', 6, 10000.0),
    ('llama.vocab_size', 4, V),
    ('tokenizer.ggml.model', 8, 'llama'),
    ('tokenizer.ggml.tokens', 9, (8, tokens)),
    ('tokenizer.ggml.unknown_token_id', 4, 0),
    ('tokenizer.ggml.add_bos_token', 4, 0),
]

for key, vtype, val in metadata:
    write_str(f, key)
    write_u32(f, vtype)
    if vtype == 8:
        write_str(f, val)
    elif vtype == 9:
        # val is (array_element_type, list_of_values)
        arr_type, arr_vals = val
        write_u32(f, arr_type)
        write_u64(f, len(arr_vals))
        for item in arr_vals:
            if arr_type == 8:
                write_str(f, item)
            elif arr_type == 4:
                write_u32(f, item)
            elif arr_type == 5:
                write_i32(f, item)
            elif arr_type == 6:
                write_f32(f, item)
    elif vtype == 4:
        write_u32(f, val)
    elif vtype == 5:
        write_i32(f, val)
    elif vtype == 6:
        write_f32(f, val)

# Tensor info table
tensors = []

def add_tensor(name, shape, dtype):
    tensors.append((name, shape, dtype))

# In GGUF, first dimension is typically the 'inner' dimension (e.g., hidden_dim)
# token_embd.weight shape should be [hidden_dim, vocab_size] = [H, V]
add_tensor('token_embd.weight', [H, V], 0)      # F32
add_tensor('output_norm.weight', [H], 0)
add_tensor('output.weight', [H, V], 0)
for layer in range(n_layers):
    add_tensor(f'blk.{layer}.attn_norm.weight', [H], 0)
    add_tensor(f'blk.{layer}.attn_q.weight', [H, H], 0)
    add_tensor(f'blk.{layer}.attn_k.weight', [H, H], 0)
    add_tensor(f'blk.{layer}.attn_v.weight', [H, H], 0)
    add_tensor(f'blk.{layer}.attn_output.weight', [H, H], 0)
    add_tensor(f'blk.{layer}.ffn_norm.weight', [H], 0)
    add_tensor(f'blk.{layer}.ffn_gate_inp.weight', [H, E], 0)
    add_tensor(f'blk.{layer}.ffn_gate_exp.weight', [H, I, E], 0)
    add_tensor(f'blk.{layer}.ffn_up_exp.weight', [H, I, E], 0)
    add_tensor(f'blk.{layer}.ffn_down_exp.weight', [I, H, E], 0)

# Compute data start position (after tensor info, aligned to 32)
data_start_pos = f.tell()
for name, shape, dtype in tensors:
    data_start_pos += 8 + len(name.encode('utf-8'))  # name_len + name
    data_start_pos += 4                                # n_dims
    data_start_pos += len(shape) * 8                   # dims
    data_start_pos += 4                                # dtype
    data_start_pos += 8                                # offset

pad = (32 - (data_start_pos % 32)) % 32
data_start_pos += pad

# Write tensor info with placeholder offsets
offset_positions = []
for name, shape, dtype in tensors:
    write_str(f, name)
    write_u32(f, len(shape))
    for d in shape:
        write_u64(f, d)
    write_u32(f, dtype)
    offset_positions.append(f.tell())
    write_u64(f, 0)  # placeholder

# Pad to data_start_pos
while f.tell() < data_start_pos:
    f.write(b'\x00')

data_start = f.tell()
assert data_start == data_start_pos

# Write tensor data and record offsets
for idx, (name, shape, dtype) in enumerate(tensors):
    numel = 1
    for d in shape:
        numel *= d
    size_bytes = numel * 4  # F32
    offset = f.tell() - data_start
    f.seek(offset_positions[idx])
    write_u64(f, offset)
    f.seek(data_start + offset + size_bytes)
    # pad to 32 alignment
    while f.tell() % 32 != 0:
        f.write(b'\x00')

# Actually write zero data
f.seek(data_start)
for name, shape, dtype in tensors:
    numel = 1
    for d in shape:
        numel *= d
    size_bytes = numel * 4
    f.write(b'\x00' * size_bytes)
    while f.tell() % 32 != 0:
        f.write(b'\x00')

# Fill in header placeholders
f.seek(8)
write_u64(f, len(tensors))
write_u64(f, len(metadata))

# Write to file
out_path = r'D:\rawrxd\synthetic_moe.gguf'
with open(out_path, 'wb') as out:
    out.write(f.getvalue())

print(f'Wrote {len(f.getvalue())} bytes to {out_path}')
print(f'Tensor count: {len(tensors)}')
print(f'Metadata count: {len(metadata)}')
print(f'Data start offset: {data_start}')
