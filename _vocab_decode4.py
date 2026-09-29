import struct

p = r"F:\~dev\qwen2.5-coder-1.5b-base.gguf"
f = open(p, "rb")

def rd(fmt):
    n = struct.calcsize(fmt)
    v = f.read(n)
    if len(v) < n:
        raise EOFError
    return struct.unpack(fmt, v)

# header
magic, = rd("<4s")
ver, = rd("<I")
n_tensors, = rd("<Q")
n_kv, = rd("<Q")
print("magic", magic, "ver", ver, "tensors", n_tensors, "kv", n_kv)

def read_str():
    n, = rd("<Q")
    return f.read(n).decode("utf-8", "replace")

def read_value(typ):
    if typ == 0: return rd("<B")[0]
    if typ == 1: return rd("<b")[0]
    if typ == 2: return rd("<H")[0]
    if typ == 3: return rd("<h")[0]
    if typ == 4: return rd("<I")[0]
    if typ == 5: return rd("<i")[0]
    if typ == 6: return rd("<Q")[0]
    if typ == 7: return rd("<q")[0]
    if typ == 8: return read_str()
    if typ == 9:
        et, n = rd("<IQ")
        if et == 8:
            return [read_str() for _ in range(n)]
        return [read_value(et) for _ in range(n)]
    if typ == 10: return rd("<Q")[0]
    raise RuntimeError(f"bad type {typ}")

meta = {}
for _ in range(n_kv):
    klen, = rd("<Q")
    key = f.read(klen).decode("utf-8", "replace")
    typ, = rd("<I")
    meta[key] = (typ, read_value(typ))

for k in ("general.architecture", "tokenizer.ggml.model",
          "tokenizer.ggml.bos_token_id", "tokenizer.ggml.eos_token_id",
          "tokenizer.ggml.add_bos_token"):
    if k in meta:
        print(k, "=", meta[k][1])

tokens = meta.get("tokenizer.ggml.tokens", (None, None))[1]
print("VOCAB", len(tokens) if tokens else None)
if tokens:
    hits = [(i, repr(t)) for i, t in enumerate(tokens)
            if t in ("hi", "Ġhi", "▁hi") or t.endswith("hi") and len(t) <= 3]
    print("HI_HITS", hits[:10])
    for i in [15, 6023, 284, 18, 16]:
        print(i, repr(tokens[i]))