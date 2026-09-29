from gguf import GGUFReader
import numpy as np
r = GGUFReader(r"F:\~dev\qwen2.5-coder-1.5b-base.gguf")
f = r.fields["tokenizer.ggml.tokens"]
# string array: data = list of offsets into the string part
str_part = f.parts[-1]
pool = bytes(str_part.data) if hasattr(str_part, "data") else None
offsets = f.data
tokens = []
for o in offsets_iter if False else []:
    pass
# walk: each entry = u32 len + bytes
off = 0
while off < len(pool):
    n = int(np.frombuffer(pool, dtype="<I", count=1, offset=off)[0]); off += 4
    tokens.append(pool[off:off+n].decode("utf-8","replace")); off += n
print("VOCAB", len(tokens))
print("tok_model probe:")
for name in ("tokenizer.ggml.model","general.architecture"):
    ff = r.fields.get(name)
    sp = ff.parts[-1]
    print(name, "=", bytes(sp.tbytes).decode("utf-8","replace") if hasattr(sp,"tbytes") else bytes(sp.data).decode("utf-8","replace"))
hits = [(i, repr(t)) for i, t in enumerate(tokens) if t in ("hi","Ġhi","▁hi")]
print("HI_HITS", hits[:10])
for i in [15, 6023, 284]:
    print(i, repr(tokens[i]))
