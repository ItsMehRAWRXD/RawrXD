#!/usr/bin/env python3
"""
Verify logits match by checking specific token probabilities.
"""
import os
import numpy as np

D2 = r"F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone"
REF = r"F:\rawrxd\evidence\deep2_gate_a\ref_head_extended"

def load_bin(path, dtype='<f4'):
    with open(path, 'rb') as f:
        data = f.read()
    return np.frombuffer(data, dtype=dtype).astype(np.float64)

# Load full logits
for pos in [9, 10]:
    print(f"\n=== pos{pos} ===")
    d2_logits = load_bin(os.path.join(D2, f"d2_logits_pos{pos}.bin"))
    ref_logits = load_bin(os.path.join(REF, f"ref_logits_pos{pos}.bin"))
    
    # Top 10 logits
    d2_top10 = np.argsort(d2_logits)[-10:][::-1]
    ref_top10 = np.argsort(ref_logits)[-10:][::-1]
    
    print(f"Deep2 top 10: {d2_top10}")
    print(f"Ref   top 10: {ref_top10}")
    
    print(f"Deep2 top 10 values: {d2_logits[d2_top10]}")
    print(f"Ref   top 10 values: {ref_logits[ref_top10]}")
    
    # Check if top-1 matches
    print(f"Top-1 match: {d2_top10[0] == ref_top10[0]} (D2={d2_top10[0]}, Ref={ref_top10[0]})")
    
    # Check specific tokens
    # The next tokens in sequence: pos9 token=5679, next should be 13; pos10 token=13, next should be...
    # Actually the greedy decode continues from the last seed token
    
    # Compute softmax and compare distributions
    d2_softmax = np.exp(d2_logits - np.max(d2_logits))
    d2_softmax = d2_softmax / np.sum(d2_softmax)
    ref_softmax = np.exp(ref_logits - np.max(ref_logits))
    ref_softmax = ref_softmax / np.sum(ref_softmax)
    
    # KL divergence
    kl = np.sum(ref_softmax * np.log(ref_softmax / (d2_softmax + 1e-20) + 1e-20))
    print(f"KL divergence: {kl:.6f}")
    
    # Cosine of logits
    cos = np.dot(d2_logits, ref_logits) / (np.linalg.norm(d2_logits) * np.linalg.norm(ref_logits))
    print(f"Logits cosine: {cos:.10f}")

# Now let's check the LM head weights in Deep2 vs the token embeddings
# The trace shows token_embd.weight at pc=0
print("\n=== Token embedding lookup (pos9) ===")
# The trace shows the embedding vector for token 5679
# Let's see if this matches what we'd get from the embedding table
# We can't easily check without the full table, but we can check pos9 vs pos10

# Load the traced token embeddings
import struct
def load_trace_embedding(pos):
    path = os.path.join(D2, f"d2_pos{pos}_blk999_pc0_token_embd.weight.bin")
    if os.path.exists(path):
        return load_bin(path)
    return None

emb9 = load_trace_embedding(9)
emb10 = load_trace_embedding(10)

if emb9 is not None and emb10 is not None:
    print(f"Pos9 embedding (token 5679): shape={emb9.shape}, mean={np.mean(emb9):.4f}, std={np.std(emb9):.4f}")
    print(f"Pos10 embedding (token 13): shape={emb10.shape}, mean={np.mean(emb10):.4f}, std={np.std(emb10):.4f}")
    cos = np.dot(emb9, emb10) / (np.linalg.norm(emb9) * np.linalg.norm(emb10))
    print(f"Embedding cosine: {cos:.6f}")
    
    # Check if these are just rows from the embedding matrix
    # They should be different for different tokens
    diff = emb10 - emb9
    print(f"Embedding diff maxabs: {np.max(np.abs(diff)):.4f}")

# The key test: compute logits manually from Deep2's post-final-norm
# and see if they match ex.Logits()
# We need the LM head weights. Let's try to dequantize token_embd.weight from GGUF
import gguf
reader = gguf.GGUFReader(r'F:\rawrxd\llama3.2-3b-Q2_K.gguf')
lm_head_weight = None
for tensor in reader.tensors:
    if tensor.name == 'token_embd.weight':
        print(f"\nLM head weight: {tensor.name}, shape={tensor.shape}, type={tensor.tensor_type}")
        # Type 14 = Q2_K
        # We'd need to dequantize it to check
        break