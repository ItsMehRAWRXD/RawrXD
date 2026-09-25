#!/usr/bin/env python3
"""Generate a synthetic MoE GGUF for expert cache certification.

This creates a tiny but structurally valid GGUF with:
- 2 layers, 4 experts, top-2 routing
- Small dimensions (H=64, I=32, V=16)
- Float32 weights for simplicity (not quantized)
- Valid tokenizer metadata (vocab=16 tokens)
"""
import struct
import numpy as np
import io


def write_u32(f, v):
    f.write(struct.pack('<I', v))

def write_u64(f, v):
    f.write(struct.pack('<Q', v))

def write_f32(f, v):
    f.write(struct.pack('<f', v))

def write_str(f, s):
    b = s.encode('utf-8')
    write_u64(f, len(b))
    f.write(b)


def write_gguf_v3_tensor_info(f, name, n_dims, dims, dtype, offset):
    """Write a single tensor info entry (GGUF v3)."""
    write_str(f, name)
    write_u32(f, n_dims)
    for d in dims:
        write_u64(f, d)
    write_u32(f, dtype)
    write_u64(f, offset)
    # v3 tensor info alignment: data_offset field (u64) after each tensor info
    write_u64(f, 0)  # data_offset (ignored by most parsers)


def generate():
    vocab_size = 16
    hidden_dim = 64
    num_layers = 2
    num_experts = 4
    num_experts_per_token = 2
    intermediate_dim = 32
    head_count = 4
    head_count_kv = 4
    head_dim = 16
    context_length = 128

    # We use GGUF v3
    # Tensor names follow what Deep2 expects:
    # Router: ffn_gate_inp.weight
    # Packed experts: ffn_gate_exp.weight, ffn_up_exp.weight, ffn_down_exp.weight

    # Build tensor data
    tensors = []

    def add_tensor(name, shape, dtype=0):
        """dtype 0 = float32 in GGML."""
        arr = np.random.randn(*shape).astype(np.float32) * 0.01
        data = arr.tobytes()
        tensors.append({
            'name': name,
            'shape': shape,
            'dtype': dtype,  # GGML_TYPE_F32 = 0
            'data': data,
            'n_elements': arr.size,
            'n_bytes': len(data)
        })

    # token embeddings
    add_tensor('token_embd.weight', (vocab_size, hidden_dim))

    # output norm
    add_tensor('output_norm.weight', (hidden_dim,))

    # output weight (shared with token_embd, but we still write it or reuse)
    add_tensor('output.weight', (vocab_size, hidden_dim))

    for layer in range(num_layers):
        p = f'blk.{layer}.'
        add_tensor(p + 'attn_norm.weight', (hidden_dim,))
        add_tensor(p + 'attn_q.weight', (hidden_dim, hidden_dim))
        add_tensor(p + 'attn_k.weight', (hidden_dim, hidden_dim))
        add_tensor(p + 'attn_v.weight', (hidden_dim, hidden_dim))
        add_tensor(p + 'attn_output.weight', (hidden_dim, hidden_dim))
        add_tensor(p + 'ffn_norm.weight', (hidden_dim,))
        # MoE router
        add_tensor(p + 'ffn_gate_inp.weight', (num_experts, hidden_dim))
        # Packed expert weights: shape[0]=intermediate, shape[1]=hidden, shape[2]=num_experts
        add_tensor(p + 'ffn_gate_exp.weight', (intermediate_dim, hidden_dim, num_experts))
        add_tensor(p + 'ffn_up_exp.weight', (intermediate_dim, hidden_dim, num_experts))
        add_tensor(p + 'ffn_down_exp.weight', (hidden_dim, intermediate_dim, num_experts))

    # Tokenizer data
    # Token strings (dummy vocab)
    tokens = [f'tok{i}'.encode('utf-8') for i in range(vocab_size)]
    # scores
    scores = np.zeros(vocab_size, dtype=np.float32)
    # token types (all normal = 1)
    token_types = np.ones(vocab_size, dtype=np.int32)

    # Now build the file
    buf = io.BytesIO()

    # Magic + version
    buf.write(b'GGUF')
    write_u32(buf, 3)  # version 3

    # Count tensors and metadata
    n_tensors = len(tensors)
    n_meta = 17  # 14 scalar/string fields + 3 tokenizer arrays

    write_u64(buf, n_tensors)
    write_u64(buf, n_meta)

    # Metadata fields
    meta_items = []

    def add_meta_str(key, value):
        meta_items.append((key, 8, value.encode('utf-8')))
    def add_meta_u32(key, value):
        meta_items.append((key, 4, struct.pack('<I', value)))
    def add_meta_i32(key, value):
        meta_items.append((key, 5, struct.pack('<i', value)))
    def add_meta_f32(key, value):
        meta_items.append((key, 6, struct.pack('<f', value)))
    def add_meta_u64(key, value):
        meta_items.append((key, 11, struct.pack('<Q', value)))

    add_meta_str('general.architecture', 'llama')
    add_meta_str('general.name', 'synthetic_moe_gate')
    add_meta_u32('llama.block_count', num_layers)
    add_meta_u32('llama.context_length', context_length)
    add_meta_u32('llama.embedding_length', hidden_dim)
    add_meta_u32('llama.feed_forward_length', intermediate_dim)
    add_meta_u32('llama.attention.head_count', head_count)
    add_meta_u32('llama.attention.head_count_kv', head_count_kv)
    add_meta_u32('llama.attention.key_length', head_dim)
    add_meta_u32('llama.attention.value_length', head_dim)
    add_meta_u32('expert_count', num_experts)
    add_meta_u32('expert_used_count', num_experts_per_token)
    add_meta_u32('expert_feed_forward_length', intermediate_dim)

    # Also add tokenizer metadata
    add_meta_str('tokenizer.ggml.model', 'gpt2')
    # Token array metadata (we'll write it as array)
    # Actually, let's add the token list as a string array
    # For simplicity, skip complex tokenizer arrays and just include basic metadata
    # The engine might not need full tokenizer to load weights.

    # Write metadata
    for key, dtype, val_bytes in meta_items:
        write_str(buf, key)
        write_u32(buf, dtype)
        if dtype == 8:
            write_u64(buf, len(val_bytes))
            buf.write(val_bytes)
        elif dtype == 4:
            buf.write(val_bytes)
        elif dtype == 5:
            buf.write(val_bytes)
        elif dtype == 6:
            buf.write(val_bytes)
        elif dtype == 11:
            buf.write(val_bytes)

    # Add tokenizer.ggml.tokens as array of strings
    write_str(buf, 'tokenizer.ggml.tokens')
    write_u32(buf, 9)  # array
    write_u32(buf, 8)  # element type = string
    write_u64(buf, vocab_size)
    for tok in tokens:
        write_u64(buf, len(tok))
        buf.write(tok)

    # Add tokenizer.ggml.scores as array of float32
    write_str(buf, 'tokenizer.ggml.scores')
    write_u32(buf, 9)  # array
    write_u32(buf, 6)  # element type = float32
    write_u64(buf, vocab_size)
    for s in scores:
        write_f32(buf, float(s))

    # Add tokenizer.ggml.token_type as array of int32
    write_str(buf, 'tokenizer.ggml.token_type')
    write_u32(buf, 9)  # array
    write_u32(buf, 5)  # element type = int32
    write_u64(buf, vocab_size)
    for t in token_types:
        write_u32(buf, int(t))

    # Tensor info section
    # Current position is end of metadata
    # Data section starts after tensor info, aligned to 32 bytes
    tensor_info_end = buf.tell() + sum(
        8 + len(t['name'].encode('utf-8')) + 4 + len(t['shape'])*8 + 4 + 8 + 8
        for t in tensors
    )
    # Align to 32 bytes
    data_offset = (tensor_info_end + 31) & ~31

    for t in tensors:
        write_str(buf, t['name'])
        write_u32(buf, len(t['shape']))
        for d in t['shape']:
            write_u64(buf, d)
        write_u32(buf, t['dtype'])
        write_u64(buf, data_offset)
        write_u64(buf, data_offset)  # data_offset field in v3
        data_offset += t['n_bytes']
        data_offset = (data_offset + 31) & ~31

    # Pad to data_offset
    current = buf.tell()
    target = (current + 31) & ~31
    buf.write(b'\x00' * (target - current))

    # Write tensor data
    for t in tensors:
        buf.write(t['data'])
        # Pad to 32-byte alignment
        pad = (32 - (buf.tell() % 32)) % 32
        buf.write(b'\x00' * pad)

    out_path = r'D:\rawrxd\synthetic_moe.gguf'
    with open(out_path, 'wb') as f:
        f.write(buf.getvalue())

    print(f"Generated: {out_path}")
    print(f"  Tensors: {len(tensors)}")
    print(f"  Layers: {num_layers}")
    print(f"  Experts: {num_experts}")
    print(f"  Experts/token: {num_experts_per_token}")
    print(f"  Hidden dim: {hidden_dim}")
    print(f"  Intermediate dim: {intermediate_dim}")
    print(f"  Vocab size: {vocab_size}")
    print(f"  File size: {len(buf.getvalue())} bytes")


if __name__ == '__main__':
    generate()
