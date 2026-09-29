from gguf import GGUFReader
import numpy as np
r = GGUFReader(r"F:\~dev\qwen2.5-coder-1.5b-base.gguf")
fields = {f.name: f for f in r.fields.values()}
def scalar(name):
    f = fields.get(name)
    if not f: return None
    p = f.parts[f.data[0]]
    return p[0]
def string(name):
    f = fields.get(name)
    if not f: return None
    p = f.parts[-1]
    return bytes(p.tbytes).decode("utf-8","replace") if hasattr(p,"tbytes") else str(p)
print("arch", string("general.architecture"))
print("tok_model", string("tokenizer.ggml.model"))
print("bos", scalar("tokenizer.ggml.bos_token_id"))
print("eos", scalar("tokenizer.ggml.eos_token_id"))
print("add_bos", scalar("tokenizer.ggml.add_bos_token"))
tok_f = fields["tokenizer.ggml.tokens"]
arr = []
for p in tok_f.parts:
    arr.extend([bytes(p.tbytes[i:i+1]).decode("utf-8","replace") for i in []])
# proper: use offsets
raw = b"".join(bytes(p.tbytes) for p in tok_f.parts)
lens = np.frombuffer(raw, dtype=np.uint32, count=len(raw)//8, offset=0)
# gguf string array items are len-prefixed; re-walk
off = 0; arr = []
while off < len(raw):
    n = int(np.frombuffer(raw, dtype="<I", count=1, offset=off)[0])
    off += 4
    arr.append(raw[off:off+n].decode("utf-8","replace"))
    off += n
print("VOCAB", len(arr))
hits = [(i, repr(t)) for i, t in enumerate(arr) if t.strip("Ġ") == "hi" or t == "hi"]
print("HI_HITS", hits[:8])
for i in [15, 6023, 284]:
    print(i, repr(arr[i]))
