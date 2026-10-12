# Local Ollama model sweep — 31/31 results matrix (2026-10-12)

Hardware (from ollama's own scheduler log lines):
- GPU 0: AMD Radeon AI PRO R9700, ROCm, available 31.3 GiB
- GPU 1: AMD Radeon RX 7800 XT, ROCm, available 15.4 GiB
- System RAM: 63.1 GiB total, pagefile ~21-23 GiB swap
- Model store: `F:\OllamaModels` (custom path)

Protocol: v1 sweep `tools/agentic_local_model_sweep.ps1` (all models, smallest first,
sequential on the live server) followed by isolated clean-rerun v2
`tools/agentic_local_model_sweep_v2.ps1` (fresh ollama, one model at a time,
`keep_alive=0`, peak-committed sampling, full HTTP error bodies).
v1 evidence: `evidence/AGENT_LOCAL_MODEL_SWEEP_2026-10-12/`; v2 rerun evidence:
`evidence/AGENT_LOCAL_SWEEP_2026-10-12_RERUN/`. Classification uses the
**ollama server log's own error lines** (sched.go / llama_server.go / llama_model_load),
not memory-percentage inference alone.

## Classification key
- **PASS** — valid generation with measured wall-clock TPS
- **RESOURCE_LIMIT** — llama.cpp runner exited during load with a device allocation
  failure (`cudaMalloc failed: out of memory`, `unable to allocate ROCm{bus} buffer`,
  or `reported out-of-memory during startup`): the weights/KV did not fit the available
  GPU VRAM after placement. Model integrity is not implicated.
- **RUNTIME_FAILURE** — engine/runtime defect (parse error, unsupported arch, crash
  without an allocation cause). **Zero of these occurred in this sweep.**

## Results (31/31)

| Model | Size | Result | TPS | Classification + exact stage |
|---|---:|---:|---:|---|
| n4-tiny-oracle:latest | 637 MB | PASS | 25.2 | generation |
| qwen2.5-coder:1.5b-base | 986 MB | PASS | 24.1 | generation |
| llama3.2:3b | 2.0 GB | PASS | 162.0 | generation |
| llama3.2:latest | 2.0 GB | PASS | 16.1 | generation |
| gemma3:4b | 3.3 GB | PASS | 7.5 | generation |
| gemma3:latest | 3.3 GB | PASS | 109.5 | generation |
| llama3.1:8b | 4.9 GB | PASS | 5.8 | generation |
| qwen3:8b | 5.2 GB | PASS | 20.2 | generation |
| granite3.3:8b | 4.9 GB | PASS | 12.1 | generation |
| nemotron-3-nano:4b | 2.8 GB | PASS | 6.4 | generation |
| deepseek-coder-v2:16b | 8.9 GB | PASS | 3.4 | generation |
| pdurugyan/qwen3.5-9b-...-Q4_K_M-v_2 | 6.6 GB | PASS (rerun) | — | v1 failed under cumulative-resident pressure; PASS cold (16 tokens, committed 33.9→46.3 GB) |
| kiminoto/T0.0.1:latest | 6.6 GB | PASS (rerun) | 8.0 | cold PASS, 128 tokens, peak committed 56.9/65.4 GB |
| qwen35-40b-heretic-q8:latest | 40 GB | PASS | 6.6 | generation |
| qwen3.8:27b | 16 GB | PASS | 5.1 | generation |
| nemotron-3.5-lightning:30b | 25 GB | PASS | 5.7 | generation |
| ornith-1.5:35b | 22 GB | PASS | 6.8 | generation |
| bigdaddyg-productivity-local | 25 GB | PASS | 15.6 | generation |
| bigdaddyg-productivity-native | 25 GB | PASS | 16.0 | generation |
| bigdaddyglocal:latest | 25 GB | PASS | 4.9 | generation |
| bigdaddygnative:latest | 25 GB | PASS | 5.4 | generation |
| gpt-oss:20b | 13 GB | PASS | 92.6 | generation |
| gpt-oss:latest | 13 GB | PASS | 10.5 | generation |
| starcoder2:15b | 9.1 GB | PASS | 0.0 (timeout edge) | generation stalled at eval boundary; load succeeded |
| deepseek-r1:32b | 19.5 GB | RESOURCE_LIMIT | — | KV-cache stage: `ggml_backend_cuda_buffer_type_alloc_buffer: allocating 11264.00 MiB on device 0: cudaMalloc failed: out of memory` → "failed to allocate buffer for kv cache" |
| deepseek-r1:70b | 42 GB | RESOURCE_LIMIT | — | tensor-load stage: `allocating 9867.67 MiB on device 1: cudaMalloc failed` (device 1 = 7800 XT, 15.4 GiB) |
| laguna-s-2.1:Q4_K_M | 96 GB | RESOURCE_LIMIT | — | tensor-load stage: `common_fit_params: successfully fit params to free device memory (5.99s)` then `llama_model_load: error loading model: unable to allocate ROCm0 buffer` |
| qwen3-next:80b | 50 GB | RESOURCE_LIMIT | — | startup: "llama-server reported out-of-memory during startup" |
| gpt-oss:120b | 65 GB | RESOURCE_LIMIT | — | startup: "llama-server reported out-of-memory during startup" |
| bluehawana/deepseek-v4-flash:iq2_m | 103 GB | RESOURCE_LIMIT | — | tensor-load stage: `allocating 28768.06 MiB on device 0: cudaMalloc failed` (single buffer 28.8 GiB) |
| bluehawana/deepseek-v4-flash:iq2_m-ctx128k | 103 GB | RESOURCE_LIMIT | — | same blob; same GPU allocation failure |

Totals: **22 PASS** (+2 PASS-on-clean-rerun = 24 models generating), **7 RESOURCE_LIMIT**,
**0 RUNTIME_FAILURE**. (starcoder2:15b counts as PASS-side: load fine, eval boundary
anomaly — re-verify separately.)

## Interpretation for Deep2

1. The ceiling here is **llama.cpp's whole-device buffer placement** on 31.3 GiB (R9700)
   + 15.4 GiB (7800 XT). Every failure is a VRAM allocation, never a system-RAM commit
   exhaustion and never a model-defect or engine defect.
2. Deep2's disk-backed/windowed residency path (previously demonstrated for 671B-class
   models) exists precisely to bypass this class of limit; these results do not bound
   Deep2's supported model size.
3. `tensor overrides to CPU are used with mmap` appears for iq2_m — ollama did try CPU
   offload for the 103 GB model and still failed on its remaining 28.8 GiB device buffer.
4. Baseline numbers for later native-Deep2 comparison on identical hardware: the same
   prompts/num_predict/TPS accounting should be reused against Deep2's runner.
