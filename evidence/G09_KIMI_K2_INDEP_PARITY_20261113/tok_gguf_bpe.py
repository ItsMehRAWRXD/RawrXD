"""Independent GPT2-BPE tokenize from GGUF vocab/merges (no weight load). Fail-closed."""
import sys, json
from pathlib import Path
from gguf import GGUFReader
from tokenizers import Tokenizer
from tokenizers.models import BPE
from tokenizers.pre_tokenizers import ByteLevel
from tokenizers.decoders import ByteLevel as ByteLevelDecoder

model_path = sys.argv[1]
prompt = Path(sys.argv[2]).read_bytes()
reader = GGUFReader(model_path)
fields = reader.fields

def get_field(name):
    if name not in fields:
        raise SystemExit(f"MISSING_FIELD {name}")
    return fields[name]

# architecture / template
arch = bytes(get_field("general.architecture").parts[-1]).decode("utf-8").rstrip("\x00")
pre = bytes(get_field("tokenizer.ggml.pre").parts[-1]).decode("utf-8").rstrip("\x00")
tmpl = bytes(get_field("tokenizer.chat_template").parts[-1]).decode("utf-8")
bos = int(get_field("tokenizer.ggml.bos_token_id").parts[-1][0]) if False else None
# bos/eos via data
import numpy as np
bos_id = int(np.frombuffer(get_field("tokenizer.ggml.bos_token_id").parts[-1], dtype="<u4")[0])
eos_id = int(np.frombuffer(get_field("tokenizer.ggml.eos_token_id").parts[-1], dtype="<u4")[0])

tok_field = get_field("tokenizer.ggml.tokens")
# tokens array: gguf stores as list of strings in parts
# Use reader.tensors? Better use field contents API
tokens = []
# GGUFReader field data for string arrays
data = tok_field.data
# In gguf-py, string arrays are in .data as list-like
if hasattr(data, "__iter__") and not isinstance(data, (bytes, bytearray)):
    tokens = [str(x) for x in data]
else:
    raise SystemExit("TOKENS_PARSE_FAIL")

merges_field = get_field("tokenizer.ggml.merges")
merges = [str(x) for x in merges_field.data]

print(f"ARCH={arch}")
print(f"TOKENIZER_PRE={pre}")
print(f"VOCAB={len(tokens)}")
print(f"MERGES={len(merges)}")
print(f"BOS={bos_id} EOS={eos_id}")
print(f"CHAT_TEMPLATE_BYTES={len(tmpl.encode('utf-8'))}")
import hashlib
print(f"CHAT_TEMPLATE_SHA256={hashlib.sha256(tmpl.encode('utf-8')).hexdigest().upper()}")

# Build BPE tokenizer (byte-level GPT2 style like llama.cpp type 2)
vocab = {t: i for i, t in enumerate(tokens)}
# merges are "a b"
merge_list = []
for m in merges:
    parts = m.split(" ", 1)
    if len(parts) == 2:
        merge_list.append((parts[0], parts[1]))

tokenizer = Tokenizer(BPE(vocab=vocab, merges=merge_list, byte_fallback=False, ignore_merges=False))
tokenizer.pre_tokenizer = ByteLevel(add_prefix_space=False)
tokenizer.decoder = ByteLevelDecoder()
# special tokens: keep as normal vocab entries; encode with special parsing by disabling
enc = tokenizer.encode(prompt.decode("utf-8"))
ids = enc.ids
print(f"PROMPT_BYTES={len(prompt)}")
print(f"PROMPT_TOKEN_COUNT={len(ids)}")
print("PROMPT_TOKEN_IDS=" + ",".join(map(str, ids)))
# Also try adding specials manually: HF may split control tokens
# Write template sidecar
Path(sys.argv[3]).write_text(tmpl, encoding="utf-8")
