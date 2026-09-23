# Inspect actual tensor names in gemma3 GGUF using raw gguf-py
from gguf import GGUFReader
import sys

path = r"D:\rawrxd\gemma3-1b-Q2_K.gguf"
reader = GGUFReader(path)

print(f"Tensor count: {len(reader.tensors)}")
print("First 20 tensor names:")
for i, t in enumerate(reader.tensors[:20]):
    print(f"  {i}: {t.name}")

# Check for token embed
embed_names = [t.name for t in reader.tensors if 'embed' in t.name.lower() or 'token' in t.name.lower()]
print(f"\nEmbed/token related tensors: {embed_names}")

# Also check exact names we look for
targets = ['token_embd.weight', 'output.weight', 'lm_head.weight', 'output_norm.weight']
for t in targets:
    found = any(tensor.name == t for tensor in reader.tensors)
    print(f"  {t}: {'FOUND' if found else 'MISSING'}")
