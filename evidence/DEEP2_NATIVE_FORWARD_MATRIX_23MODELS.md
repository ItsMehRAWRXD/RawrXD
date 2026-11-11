# Deep2 native single-forward sweep — 23-model coverage matrix (2026-10-12)

Source: single-forward argmax probe over local Ollama-managed blobs, run with
Deep2's real-weight forward path on this machine (R9700 + RX 7800 XT).
This records execution coverage, NOT decode performance: every row is ONE
forward, timings include model load from `F:\OllamaModels\blobs` and are
dominated by it. GPU-fallback notices are printed because this box runs the
quant-dot path on CPU (see "GPU coverage" below).

## Coverage

| model | size GB | arch | blocks | embd | forward | time s | fallback notice |
|---|---:|---|---:|---:|---|---:|---|
| RageBait/LadySophiaNoctua | 2.02 | llama | 28 | 3072 | argmax=2 (max_logit 4.96) | 15.7 | k-quant dot: force_cpu |
| nemotron-3-nano:4b | 2.84 | nemotron_h | 42 | 3136 | argmax=104632 (8.69) | 22.7 | legacy quant dot: force_cpu (ssm_in) |
| gemma3:4b | 3.34 | gemma3 | 34 | 2560 | argmax=117157 (65.33) | 24.4 | k-quant dot: force_cpu |
| llama3.1:8b | 4.92 | llama | 32 | 4096 | argmax=128006 (20.18) | 37.0 | k-quant dot: force_cpu |
| granite3.3:8b | 4.94 | granite | 40 | 4096 | argmax=110 (171.93) | 37.7 | k-quant dot: force_cpu |
| qwen3:8b | 5.23 | qwen3 | 36 | 4096 | argmax=82 (13.21) | 41.0 | k-quant dot: force_cpu |
| deepseek-coder-v2:16b | 8.91 | deepseek2 | 27 | 2048 | argmax=93 (23.63) | 48.1 | legacy quant CPU dequant, no GPU kernel |
| starcoder2:15b | 9.07 | starcoder2 | 40 | 6144 | argmax=3 (10.43) | 47.7 | legacy quant CPU dequant, no GPU kernel |
| deepseek-r1:32b | 19.85 | qwen2 | 64 | 5120 | argmax=198 (12.89) | 133.1 | k-quant dot: force_cpu |
| **nemotron-3.5-lightning:30b** | 25.43 | nemotron_h_moe | 53 | 2688 | **argmax=50988 (10.71)** | 124.3 | legacy quant dot: force_cpu (ssm_in) |
| bigdaddyg-productivity-local | 25.46 | llama | 80 | 8192 | **argmax=0, max_logit=0.000000** | 218.0 | legacy quant CPU dequant, no GPU kernel |
| **deepseek-r1:70b** | 42.52 | llama | 80 | 8192 | **argmax=14924 (12.48)** | 359.0 | k-quant dot: force_cpu |
| EXEC_FAIL rows (10) | | | | | | | |
| library/phi3:mini | 2.18 | phi3 | 32 | 3072 | EXEC_FAIL | 12.2 | |
| qwen35-40b-heretic-q8 | 2.18 | phi3 | 32 | 3072 | EXEC_FAIL | 11.7 | (phi3 path — same failure as phi3:mini) |
| pdurugyan/qwen3.5-9b-...-v2 | 5.63 | qwen35 | 32 | 4096 | EXEC_FAIL | 26.9 | |
| kiminoto/T0.0.1 | 6.59 | qwen35 | 32 | 4096 | EXEC_FAIL | 32.0 | (qwen35 — same failure as pdurugyan) |
| bigdaddyg-16gb | 13.79 | gptoss | 24 | 2880 | EXEC_FAIL | 64.6 | (gptoss path) |
| qwen3.8:27b | 16.81 | qwen35 | 65 | 5120 | EXEC_FAIL | 79.9 | (qwen35 — same) |
| ornith-1.5:35b | 21.71 | qwen35moe | 41 | 2048 | EXEC_FAIL | 107.9 | (moe variants of qwen35) |
| qwen3-next:80b | 50.35 | qwen3next | 48 | 2048 | EXEC_FAIL | 224.4 | |
| gpt-oss:120b | 65.37 | gptoss | 36 | 2880 | EXEC_FAIL | 302.2 | (gptoss — same as 16gb) |
| laguna-s-2.1:Q4_K_M | 96.03 | laguna | 48 | 3072 | EXEC_FAIL | 449.2 | |
| bluehawana/deepseek-v4-flash:iq2_m | 104.00 | deepseek4 | 43 | 4096 | EXEC_FAIL | 531.3 | |

Summary: 13/23 one-forward OK (56.5%), 10/23 EXEC_FAIL (43.5%). Largest
successful forward: DeepSeek-R1 70B at 42.52 GB — larger than anything the
installed ollama could load on this hardware (its GPU-VRAM ceiling was ~20GB
of weights).

## Defect triage for gate 1 (correctness)

1. **P0 — `bigdaddyg-productivity-local`: argmax=0 with max_logit=0.000000.**
   Zero-logit output is suspicious for incomplete forward or a zeroed read
   (its 80 blocks/8192 embd is a large llama). Needs full-logit distribution
   and block-completion count before treating it as valid.
2. **P1 — EXEC_FAIL failure-mode grouping (by architecture family, likely
   shared root causes, not 10 independent defects):**
   - `phi3` path (2 models: phi3:mini, qwen35-40b marked phi3 — possibly a
     metadata/arch-detection mismatch itself: 2.18 GB 40B-quant parsed as phi3
     blocks=32 embd=3072)
   - `qwen35` family (4: pdurugyan, kimi, qwen3.8:27b, ornith-1.5 qwen35moe)
   - `gptoss` family (2: bigdaddyg-16gb, gpt-oss:120b)
   - remaining singles: qwen3-next:80b (qwen3next), laguna (laguna),
     deepseek4 (iq2_m)
3. **P2 — GPU coverage.** All successful rows print CPU fallbacks
   (`k-quant dot: force_cpu`, `legacy quant dot: force_cpu`, `legacy quant
   type dequantised on CPU, no GPU kernel`). Timings are therefore CPU-path.
   The `quant_dot` Vulkan path exists in tools/shaders and the new
   R9700ExpertLruPolicy/3rdparty/r9700-stack references are the natural base
   for closing this gap; Nemotron's `blk.0.ssm_in` and the common
   `attn_q` Q4_K/Q6_K dots are the highest-frequency kernels.

## Gate-3 prerequisite already established

`nemotron-3.5-lightning:30b` (nemotron_h_moe, 53 blocks, embd 2688) reached a
finite argmax (50988, max_logit 10.71) in a single forward — the prerequisite
for the progressive context certification (4K → 32K → 128K → 512K → 1M) that
also answers the unanswered profiler questions (prompt tokens, n_ctx, KV-cache
capacity, attended positions).

## Cross-reference with the ollama sweep

Of the 10 EXEC_FAIL models, all but phi3:mini were also in the 31-model ollama
sweep: kimi/pdurugyan PASS in ollama (and in Deep2's isolated rerun via a
different harness), qwen3-next:80b/gpt-oss:120b/laguna/iq2_m RESOURCE_LIMIT in
ollama — meaning Deep2's failures there are NOT inheritors of ollama's limits
but distinct Deep2-side gaps. Conversely Deep2 completed forwards on r1:70b,
r1:32b, nemotron-lightning-30b, nemotron-nano-4b, deepseek-coder-v2:16b where
ollama 500'd on several. The two engines' failure sets are largely disjoint —
which is exactly the capability-comparison data worth completing.
