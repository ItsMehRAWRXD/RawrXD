from gguf import GGUFReader

p = r"F:\OllamaModels\Qwen3.6-35B-A3B-GGUF\Qwen3.6-35B-A3B-Q4_K_M.gguf"
r = GGUFReader(p)
for key in ("tokenizer.ggml.tokens", "tokenizer.ggml.merges", "tokenizer.ggml.add_bos_token"):
    f = r.fields[key]
    print(key, "parts", len(f.parts), "data", len(f.data))
    print("parts_head", repr(f.parts[:3]))
    print("data_head", repr(f.data[:3]))
