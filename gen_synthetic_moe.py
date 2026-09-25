import struct
import io
import os

def write_u32(f, v): f.write(struct.pack('<I', v))
def write_u64(f, v): f.write(struct.pack('<Q', v))
def write_i32(f, v): f.write(struct.pack('<i', v))
def write_f32(f, v): f.write(struct.pack('<f', v))
def write_str(f, s):
    b = s.encode('utf-8')
    write_u64(f, len(b))
    f.write(b)

def align8(f):
    p = f.tell()
    pad = (8 - (p % 8)) % 8
    f.write(b'\x00' * pad)
    return f.tell()

def align32(f):
    p = f.tell()
    pad = (32 - (p % 32)) % 32
    f.write(b'\x00' * pad)
    return f.tell()

# Model dims
V = 16
H = 64
I = 32
E = 4
n_layers = 2

f = io.BytesIO()

# Header
write_u32(f, 0x46554747)  # magic 'GGUF'
write_u32(f, 2)             # version 2
write_u64(f, 0)             # tensor count placeholder
write_u64(f, 0)             # metadata count placeholder

metadata = []

def add_meta_str(key, val):
    metadata.append(('str', key, val))

def add_meta_u32(key, val):
    metadata.append(('u32', key, val))

def add_meta_f32(key, val):
    metadata.append(('f32', key, val))

def add_meta_i32(key, val):
    metadata.append(('i32', key, val))

def add_meta_u64(key, val):
    metadata.append(('u64', key, val))

add_meta_str('general.architecture', 'llama')
add_meta_str('general.name', 'synthetic_moe')
add_meta_u32('general.alignment', 32)
add_meta_u32('llama.block_count', n_layers)
add_meta_u32('llama.context_length', 128)
add_meta_u32('llama.embedding_length', H)
add_meta_u32('llama.feed_forward_length', I)
add_meta_u32('llama.attention.head_count', 4)
add_meta_u32('llama.attention.head_count_kv', 4)
add_meta_u32('llama.attention.layer_norm_rms_epsilon', 0x3A4CCCCD)  # 0.00001f as u32 bits
add_meta_u32('llama.expert_count', E)
add_meta_u32('llama.expert_used_count', 2)
add_meta_u32('llama.rope.dimension_count', 64)
add_meta_f32('llama.rope.freq_base', 10000.0)
add_meta_u32('llama.vocab_size', V)

# Write metadata count
meta_count_pos = f.tell() - 8
for m in metadata:
    t, key, val = m
    write_str(f, key)
    if t == 'str':
        write_u32(f, 8)  # GGUF_TYPE_STRING
        write_str(f, val)
    elif t == 'u32':
        write_u32(f, 4)  # GGUF_TYPE_UINT32
        write_u32(f, val)
    elif t == 'i32':
        write_u32(f, 5)  # GGUF_TYPE_INT32
        write_i32(f, val)
    elif t == 'f32':
        write_u32(f, 6)  # GGUF_TYPE_FLOAT32
        write_f32(f, val)
    elif t == 'u64':
        write_u32(f, 10) # GGUF_TYPE_UINT64
        write_u64(f, val)
    align8(f)

meta_end = f.tell()

# Tensor info table
tensors = []

def add_tensor(name, shape, dtype):
    tensors.append((name, shape, dtype))

add_tensor('token_embd.weight', [V, H], 0)      # F32
add_tensor('output_norm.weight', [H], 0)
add_tensor('output.weight', [V, H], 0)

for layer in range(n_layers):
    add_tensor(f'blk.{layer}.attn_norm.weight', [H], 0)
    add_tensor(f'blk.{layer}.attn_q.weight', [H, H], 0)
    add_tensor(f'blk.{layer}.attn_k.weight', [H, H], 0)
    add_tensor(f'blk.{layer}.attn_v.weight', [H, H], 0)
    add_tensor(f'blk.{layer}.attn_output.weight', [H, H], 0)
    add_tensor(f'blk.{layer}.ffn_norm.weight', [H], 0)
    add_tensor(f'blk.{layer}.ffn_gate_inp.weight', [E, H], 0)
    add_tensor(f'blk.{layer}.ffn_gate_exp.weight', [E, I, H], 0)
    add_tensor(f'blk.{layer}.ffn_up_exp.weight', [E, I, H], 0)
    add_tensor(f'blk.{layer}.ffn_down_exp.weight', [E, H, I], 0)

# Compute data offsets
data_start = f.tell()
for name, shape, dtype in tensors:
    name_b = name.encode('utf-8')
    data_start += 8 + len(name_b)  # name_len + name
    data_start += 4                # n_dims
    data_start += len(shape) * 8   # dims
    data_start += 4                # dtype
    data_start += 8                # offset
    data_start = (data_start + 7) & ~7  # align8 after each tensor info

data_start = (data_start + 31) & ~31  # align32 before data

# Write tensor info
tensor_info_start = f.tell()
for name, shape, dtype in tensors:
    write_str(f, name)
    write_u32(f, len(shape))
    for d in shape:
        write_u64(f, d)
    write_u32(f, dtype)
    # offset is relative to data_start
    write_u64(f, 0)  # placeholder
    align8(f)

tensor_info_end = f.tell()

# Pad to data_start
while f.tell() < data_start:
    f.write(b'\x00')

# Write tensor data and fix offsets
f.seek(tensor_info_start)
for name, shape, dtype in tensors:
    write_str(f, name)
    write_u32(f, len(shape))
    for d in shape:
        write_u64(f, d)
    write_u32(f, dtype)
    offset = f.tell() - data_start + 8  # offset relative to data_start
    write_u64(f, offset)
    align8(f)

# Actually write tensor data
f.seek(data_start)
for name, shape, dtype in tensors:
    numel = 1
    for d in shape:
        numel *= d
    size_bytes = numel * 4  # F32
    f.write(b'\x00' * size_bytes)
    align32(f)

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
