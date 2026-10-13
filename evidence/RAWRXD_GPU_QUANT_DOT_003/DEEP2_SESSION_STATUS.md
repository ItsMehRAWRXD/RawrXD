# Deep2 Native Inference — Session Status (2026-10-12)

## CLOSED (with measured receipts)

### 1. DeepSeek-Coder-V2 (deepseek2) — full-logit parity with llama.cpp — PASS
Prompt tokens [1, 185] on models/deepseek-coder-v2_16b.gguf, CPU-pinned.

| Position | Deep2 argmax | llama.cpp argmax | Cosine  | Top-5 |
|----------|--------------|------------------|---------|-------|
| 0        | 185 (7.542)  | 185 (7.514)      | 0.99981 | identical set and order (185/708/4991/21329/2919) |
| 1        | 300 (8.603)  | 300 (8.534)      | >=0.9998| same set (300/391/207/185/595 vs 300/207/391/185/595) |

Reference: upstream llama.cpp built from commit c479922ac520a08969b4c1dc154d7bbb3c386d85
(tools/llama_dump_internals.cpp, scheduler eval-callback node capture).

Root causes fixed (all verified against the reference ggml binaries):
- Router weight transformation: Deep2 renormalised the top-6 softmax
  probabilities to sum to 1; this model's GGUF has no expert_weights_norm,
  so llama.cpp keeps the raw probabilities (sum ~0.18-0.45, ~2.25x inflation).
  Fixed in OpRouterTopK plus spec fields expert_weights_norm /
  expert_weights_scale read from the GGUF.
- Dual-bank MoE gate: the gate was set equal to the up projection (identity
  gate). DeepSeek-Coder-V2 ships separate ffn_gate_exps and ffn_up_exps;
  implemented the real gate projection (CPU dequant + double dot, and the
  GPU dispatch path).
- RoPE pairing: Deep2 used NEOX split-half pairs; llama.cpp uses adjacent
  pairs (llama_model_rope_type -> NORM for DEEPSEEK2). Verified against the
  reference ggml binary: NORMAL pairing reproduces llama.cpp's post-rope Qcur
  to cos 1.0000000 / RMS 1.45e-4.
- Diagnostic capture fix: MlaDecompress published hidden_ (i.e. q) into arena
  "kv" instead of the K stream.

### 2. Zero-logit model (bigdaddyg-productivity-local, llama 80 blocks) — PASS
Root cause: the GGUF has no llama.rope.freq_base, so pow(0, -2k/n) = +inf and
position * inf = NaN from rotary pair 1 onward. Fixed by defaulting to 10000.0
(llama.cpp's own default) in both the ingest and RopeAngle.
Result: 1123-op forward with zero NaNs; full-logit parity vs llama.cpp
cos = 0.9989887, argmax 1 = 1, 32000/32000 finite.

### 3. Native GPU quant-dot (R9700) — PASS
Real GGUF weights, Vulkan kernel vs two independent references (ggml dequant +
float dot, and an independent CPU integer-lane decoder):
- Q4_K (llama3.1:8b blk.0.ffn_gate.weight, ne=[4096,14336]): cos 1.0000000000, rel 2.86e-07
- Q6_K (blk.0.ffn_down.weight, ne=[14336,4096]): cos 1.0000000000, rel 6.71e-08

### 4. GPU-only sustained decode — PASS (correctness), TPS measured
- deepseek-coder-v2, 128 tokens: gpu_calls=4,986,624 cpu_calls=0 fallback=<none>;
  decode TPS 0.87 (kernel-bound: GPU_KERNEL_MS 92.5s vs SUBMIT_MS 0.5s)
- llama3.1:8b blob, 128 tokens: gpu_calls=1,857,600 cpu_calls=0 fallback=<none>;
  decode TPS 0.50
- llama3.2:3b blob: gpu_calls=591 cpu_calls=0 fallback=<none>, GPU==CPU at
  cos 0.9997/0.9947

## OPEN DEFECT (new, localized)

### Engine diverges from llama.cpp on llama3.2:3b AND qwen2.5-coder-1.5b
Symptom: Deep2's GPU and CPU paths agree with each other but disagree with
llama.cpp, so this is an engine (architecture/numerics) defect, not a GPU/CPU
dispatch issue.

| Model | Evidence |
|-------|----------|
| qwen2.5-coder-1.5b | Deep2 first-token logits vs llama.cpp: cos 0.30, max_abs 27.75; Deep2 argmax 94753 (id 729 correct) |
| llama3.2:3b | Deep2 argmax 2 at pos 0 (reference 791); per-op walk: block 0 matches at <=3e-3, from block 1 a ~1% relative error appears on the large-magnitude residual elements (362.03 vs 365.60, -333.77 vs -337.06) and persists through all 28 layers |

Per-op evidence (llama3.2:3b, position 0): blk00 pre-wo attn cos 1.0 (1.1e-4),
post-wo cos 0.999996, block residual cos 0.99997, ffn_out cos 0.99996;
blk01 pre/post-wo still ~0.999, but the block residual then shows the ~1% bias
on the dominant elements. Layer 0's q/k/v match the reference exactly
(cos 1.0, max 2e-6).

Next diagnostic: bisect blk01's FFN (gate/up/swiglu/down) and attention value
path against the reference ffn_gate/ffn_up/ffn_out node dumps captured in
C:\Users\Garrett\AppData\Local\Temp\kilo\parity\l32_ref2 (nodes Qcur-, Kcur-,
Vcur-, kqv_out-, attn_out-, l_out-, ffn_gate-, ffn_up-, ffn_out-, result_norm).

## NOT CERTIFIED
- Autonomous agentic E2E (calc.cpp repair): the harness
  (tools/deep2_agentic_loop.cpp) now has the five audited fixes (incremental
  KV context, assistant-history preservation, fail-closed action parsing,
  independent verification, live logging) plus a verified tokenizer round-trip,
  but the available small models exhibit the engine defect above, so no
  coherent tool call can be produced yet.
- llama3.1:8b reference parity for full logits beyond the Deep2-internal
  GPU==CPU comparison; llama3.2 is now included in the open defect.

## Reproducers
- GPU quant-dot parity: tools\gpu_quant_dot_realweights.exe --model <gguf> --weights <tensor> --rows 128
- GPU certify: tools\deep2_gpu_certify.exe --model <gguf> --tokens "1 185" --dump <dir>
- Reference internals: llama_dump_internals.exe <gguf> <tokens.txt> <outdir> <n_vocab>
- Deep2 parity trace: tools\deep2_parity_trace.exe --model <gguf> --tokens "1 185" --outdir <dir>
- Agentic loop: tools\deep2_agentic_loop.exe --model <gguf> --task <task.md> --workdir <dir> --max-steps 8 --max-new 200
