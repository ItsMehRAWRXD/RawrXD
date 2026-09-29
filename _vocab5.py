from gguf import GGUFReader
r = GGUFReader(r"F:\~dev\qwen2.5-coder-1.5b-base.gguf")
f = r.fields["tokenizer.ggml.tokens"]
print("type", f.types)
d = f.data
print("data type", type(d), "len", len(d))
try:
    part = d[0]
    print("item type", type(part), repr(part)[:80])
except Exception as e:
    print("ERR", e)
