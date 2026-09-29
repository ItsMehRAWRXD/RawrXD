from gguf import GGUFReader
r = GGUFReader(r"F:\~dev\qwen2.5-coder-1.5b-base.gguf")
toks = None
typ = None
for field in r.fields.values():
    if field.name == "tokenizer.ggml.tokens":
        toks = field
for f in r.fields.values():
    if f.name in ("tokenizer.ggml.model","general.architecture","tokenizer.ggml.bos_token_id","tokenizer.ggml.eos_token_id","tokenizer.ggml.add_bos_token"):
        try:
            print(f.name, "=", [bytes(part.tbytes).decode("utf-8","replace") if part.tbytes else part.as_int() if hasattr(part,'as_int') else part.parts[0][0] for part in f.parts][:1])
        except Exception as e:
            print(f.name, "ERR", e)
if toks:
    import numpy as np
    arr = []
    for part in toks.data:
        try:
            arr.append(bytes(part.tbytes).decode("utf-8","replace"))
        except Exception:
            arr.append(str(part))
    print("VOCAB_SIZE", len(arr))
    hits = [(i,repr(t)) for i,t in enumerate(arr) if t in ("hi","▁hi","Ġhi","hi\n")]
    print("HI_TOKENS", hits[:6])
    for i in [15,6023]:
        print(i, repr(arr[i]))
