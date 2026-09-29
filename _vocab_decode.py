from gguf import GGUFReader
r = GGUFReader(r"F:\~dev\qwen2.5-coder-1.5b-base.gguf")
toks = None
for field in r.fields.values():
    if field.name == "tokenizer.ggml.tokens":
        import numpy as np
        toks = [bytes(x.tbytes).decode("utf-8","replace") if hasattr(x,'tbytes') else str(x) for x in field.data]
        break
if toks is None:
    print("NO_TOKENS_FIELD")
else:
    ids = [15, 284, 18, 16, 304, 24, 20613, 21, 19, 1733, 6023]
    for i in ids:
        print(i, repr(toks[i]) if i < len(toks) else "OOR")
