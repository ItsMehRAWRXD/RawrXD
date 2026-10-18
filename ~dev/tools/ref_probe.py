# Reference metadata probe — Qwen2.5-Coder-32B-Instruct-Q4_K_M
# Prints the architectural values a correct forward pass must use.
import numpy as np
from gguf import GGUFReader

MODEL = r"F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf"

r = GGUFReader(MODEL)

print("=== METADATA (raw parts) ===")
for key in sorted(r.fields.keys()):
    f = r.fields[key]
    if not any(s in key for s in ("rope", "epsilon", "head_count", "embedding_length",
                                  "block_count", "feed_forward", "context_length",
                                  "attention.key_length", "attention.value_length",
                                  "expert")):
        continue
    parts = []
    for p in f.data:
        try:
            v = np.asarray(p).ravel()
            parts.append(v.tolist() if v.size > 1 else v.item())
        except Exception:
            parts.append(str(p))
    print(f"{key} = {parts}")

print("\n=== TENSOR TYPES (GGML enum) ===")
tm = {t.name: t.tensor_type for t in r.tensors}
interesting = [
    "token_embd.weight", "output.weight", "output_norm.weight",
    "blk.0.attn_norm.weight", "blk.0.attn_q.weight", "blk.0.attn_k.weight",
    "blk.0.attn_v.weight", "blk.0.attn_q.bias", "blk.0.attn_k.bias",
    "blk.0.attn_v.bias", "blk.0.attn_output.weight", "blk.0.ffn_norm.weight",
    "blk.0.ffn_gate.weight", "blk.0.ffn_up.weight", "blk.0.ffn_down.weight",
]
for n in interesting:
    print(f"{n}: type={tm.get(n, 'MISSING')}")

print("\n=== TENSOR SHAPES (GGUF order: dim0 fastest) ===")
shapes = {t.name: t.shape for t in r.tensors}
for n in interesting:
    print(f"{n}: shape={shapes.get(n, 'MISSING')}")

print("\n=== BIAS AUDIT ===")
bias = [n for n in names] if False else [t.name for t in r.tensors if "bias" in t.name]
print(f"total bias tensors: {len(bias)}")
kinds = {}
for b in bias:
    kind = b.split(".")[-2] if b.count(".") >= 2 else b
    kinds[b.replace("blk.0.", "").replace(".bias", "")] = kinds.get(
        b.replace("blk.0.", "").replace(".bias", ""), 0) + 1
print(f"bias kinds on blk.0 (count across all layers):")
for k in sorted(set(b.replace("blk.0.", "") for b in bias if b.startswith("blk.0."))):
    cnt = sum(1 for b in bias if b == "blk.0." + k)
    print(f"  {k}: {cnt} per layer")