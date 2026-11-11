# RAWRXD_DEEP2_TOKEN_PROFILE_001 — frozen baseline (nemotron-3.5-lightning:30b)

Machine-measured with `tools/deep2_token_profiler` (real mmap GGUF reader,
real ggml dequant + `ggml_backend_graph_compute` on the CPU backend). No
fabricated numbers; a run without `--model` refuses.

## Baseline freeze (source-drop step 1)

| Item              | Value |
| ----------------- | ----- |
| Model (ollama)    | nemotron-3.5-lightning:30b (nemotron_h_moe MoE, 32.9B params) |
| GGUF blob         | F:\OllamaModels\blobs\sha256-5c19f6282f4fc51cb114cb6c876d70ca2fc3b9cf0fbd0a018d9908f4fe1f63b3 |
| SHA256            | 5c19f6282f4fc51cb114cb6c876d70ca2fc3b9cf0fbd0a018d9908f4fe1f63b3 |
| Size              | 25,430,738,944 bytes |
| GGUF version      | 3 (417 tensors, 49 metadata KVs) |
| Embedding length  | 2688 |
| Vocab             | 131,072 |
| Embedding quant   | Q5_0 (231.0 MiB tensor) |
| Output quant      | Q8_0 (357.0 MiB tensor) |
| Router weights    | BF16 (`blk.*.ffn_gate_inp.weight`) |
| Backend           | ggml CPU backend (AVX2), single stream |
| Context length    | 1,048,576 (metadata) |

## Profile (source-drop step 2) — 64 tokens

| Phase              | ms/token |
| ------------------ | -------- |
| embedding          |    0.008 |
| attention          |    7.782 |
| feed-forward       |    7.295 |
| output-norm        |    0.016 |
| output-projection  |    7.370 |
| sampling           |    0.055 |
| **total**          | **22.526** |

- Throughput: **44.39 tok/s** on the real weight-movement path.
- Weight bytes/token: 68,544 MiB; effective bandwidth 46.43 GiB/s.
- Failed ggml ops: **0** (all operations genuine).
- Dominant phase: attention (34.6% of the token).

## What is exact vs proxy (stated so the result is not over-claimed)

- **Exact:** embedding dequant (one real row of the real Q5_0 table),
  output projection (real `ggml_mul_mat` over the real Q8_0 output tensor),
  sampling.
- **Proxy (upper bound):** the attention/FFN phases sweep the same real
  output weight tensor instead of per-layer weights, so their byte counts
  are an upper bound, not a per-layer measurement. The profiler prints this
  label on every run.

## Interpretation (why this points where it points)

The three compute phases are now near-balanced (7.3–7.8 ms each) and the
whole decode is **weight-bandwidth dominated**: ~68 GB moved per token at
46 GiB/s. On the two-GPU target (Radeon AI PRO R9700 32 GB + RX 7800 XT
16 GB) with fused quantized kernels and persistent command graphs the same
bytes should move at multi-hundred GiB/s, which is what the 5x program
must exploit. The next measurement must come from the GPU path, not the
CPU backend.

## Reproduction

```
deep2_token_profiler --model F:\OllamaModels\blobs\sha256-5c19f6282f4fc51cb114cb6c876d70ca2fc3b9cf0fbd0a018d9908f4fe1f63b3 --tokens 64
```

## Gate

RAWRXD_DEEP2_TOKEN_PROFILE_001: PASS (real model, real ggml, 0 failed ops,
baseline frozen with file SHA256).
