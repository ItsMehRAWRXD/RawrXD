# Measure-Deep2Native.ps1 — Native Deep2 Benchmark Harness

## Purpose
Bypass HTTP/Ollama entirely. Measures native Deep2 TPS through the real C++ inference path:

```
GGUF model
  ↓
rawrxd_run_modelname_001.exe (native binary)
  ↓
Deep2Engine::loadModel() → generateStream()
  ↓
native Vulkan or CPU kernels
  ↓
measured decode TPS
```

## Why this matters

The previous `Measure-Deep2Concurrency.ps1` used `/api/generate` on `:11434`, which may route through Ollama/llama.cpp rather than Deep2. This script uses the actual Deep2 C++ engine compiled into `rawrxd_run_modelname_001.exe`.

## Quick Start — Single model, single stream

```powershell
# Native single-stream with gemma3-1b (available locally)
pwsh -ExecutionPolicy Bypass -File .\Measure-Deep2Native.ps1 `
  -Model "gemma3-1b-Q2_K" `
  -Prompt "Write a compact C++ function that sums an array of 64-bit integers." `
  -MaxTokens 256 `
  -Runs 5
```

## With Vulkan GPU acceleration

```powershell
pwsh -ExecutionPolicy Bypass -File .\Measure-Deep2Native.ps1 `
  -Model "gemma3-1b-Q2_K" `
  -Prompt "Write a compact C++ function that sums an array of 64-bit integers." `
  -MaxTokens 256 `
  -Runs 5 `
  -Vulkan
```

## For larger models (when available)

```powershell
# llama3.2-3b (available locally)
pwsh -ExecutionPolicy Bypass -File .\Measure-Deep2Native.ps1 `
  -Model "llama3.2-3b-Q2_K" `
  -Prompt "Write a compact C++ function that sums an array." `
  -MaxTokens 256 `
  -Runs 5

# phi3-mini (available locally)
pwsh -ExecutionPolicy Bypass -File .\Measure-Deep2Native.ps1 `
  -Model "phi3-mini-Q2_K" `
  -Prompt "Write a compact C++ function that sums an array." `
  -MaxTokens 256 `
  -Runs 5
```

## Model availability status

| Model | Status | Location |
|-------|--------|----------|
| gemma3-1b-Q2_K | ✅ Available | D:\rawrxd\gemma3-1b-Q2_K.gguf |
| llama3.2-3b-Q2_K | ✅ Available | D:\rawrxd\llama3.2-3b-Q2_K.gguf |
| llama3.2-3b-Q3_K_S | ✅ Available | D:\rawrxd\llama3.2-3b-Q3_K_S.gguf |
| phi3-mini-Q2_K | ✅ Available | D:\rawrxd\phi3-mini-Q2_K.gguf |
| Nemotron 30B / 3.5 Lightning | ❌ Not found locally | Must be downloaded |

## Nemotron 30B — acquiring the model

The original target model `nematron-3.5-lightning:30b` (or similar) is **not present** in the current environment. Options:

1. **Download via Ollama:**
   ```powershell
   ollama pull nemotron/mini:latest
   # or search for nematron-30b variants
   ```

2. **Download via huggingface-cli:**
   ```powershell
   huggingface-cli download nvidia/Nemotron-3.5-Lightning-30B-GGUF --local-dir D:\rawrxd
   ```

3. **Use a compatible model** (e.g., Llama 3.2 3B) for initial native pipeline validation, then switch to Nemotron once available.

## Outputs

```text
native_deep2_results/
  runs.csv          — per-run metrics
  summary.csv       — aggregate statistics
  run_1_stdout.txt  — generated text
  run_1_stderr.txt  — engine diagnostics + receipt
  DEEP2_NATIVE_BENCHMARK_001.txt — authority receipt
```

## Metrics captured

| Field | Source | Authority |
|-------|--------|-----------|
| `generated_tokens` | Engine callback count | ✅ Native |
| `reported_tps` | Engine's own `tokenCount / genMs` | ✅ Native (secondary) |
| `wall_tps` | PowerShell `Start-Process` wall time | ✅ Harness |
| `wall_ms` | `(Get-Date)` delta around process | ✅ Harness |
| `model_bytes` | `Get-Item Length` | ✅ Exact |
| `model_sha256` | `SHA256.ComputeHash` | ✅ Verified |

## Comparison: Ollama vs Native

| Aspect | Ollama / :11434 | Native Deep2 (this script) |
|--------|-----------------|---------------------------|
| Inference engine | Ollama's llama.cpp | Deep2Engine (custom) |
| Quant kernels | llama.cpp q4/q5/q6 | Deep2 QuantKernelRegistry |
| GPU backend | CUDA/Metal/Vulkan via llama.cpp | Native Vulkan (Deep2) |
| Token counting | Ollama's eval_count | Deep2 callback count |
| HTTP overhead | Yes (TCP loopback) | No |
| TPS authority | Ollama-reported | Native + harness wall time |

## Concurrency measurement (1→2→3)

The native executable `rawrxd_run_modelname_001.exe` currently appears to be single-stream only. For concurrent native measurement, options:

1. **Parallel processes:** Launch multiple `rawrxd_run_modelname_001.exe` instances simultaneously via `Start-Job` (same as `Measure-Deep2Concurrency.ps1` approach)
2. **Extend the C++ binary:** Add concurrent stream support to the benchmark executable
3. **Use the Deep2 server:** Run `deep2_server.exe` on a non-default port and submit concurrent requests

For now, single-stream native TPS establishes the baseline. Concurrent native measurement requires either parallel process orchestration or server-based submission.

## Authority receipt flags

```text
MODE=NATIVE_MEASUREMENT_ONLY
NATIVE_CHAIN=PASS
NO_HTTP_INTERMEDIATE=PASS
EVAL_COUNT_FROM_NATIVE=PASS
WALL_TIME_FROM_HARNESS=PASS
```
