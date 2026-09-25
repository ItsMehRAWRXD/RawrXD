# RAWRXD_REAL_GGUF_PARITY_001

No new dependencies. C++20 + the existing Deep2 production library only.

This closes the missing **real-GGUF token/logit backend parity** surface without
requiring llama.cpp, Ollama, Python, NumPy, JSON libraries, or another model
runner.

## What it proves

For the exact same real GGUF, exact tokenizer, exact prompt, exact teacher-forced
decode sequence:

1. Run a fresh **CPU Deep2 reference**.
2. Hash the complete GGUF with source-only SHA-256.
3. Record the full vocabulary logits for every decode step.
4. Record deterministic greedy token IDs.
5. Destroy/unload the CPU engine.
6. Load a fresh engine with **strict Vulkan / no CPU fallback**.
7. Re-tokenize the prompt and require identical prompt token IDs.
8. Teacher-force the CPU greedy sequence through Vulkan.
9. Compare **every vocabulary logit** at every step:
   - max absolute error
   - mean absolute error
   - RMS error
   - normalized maximum relative error
   - cosine similarity
   - top-1 token
   - top-K intersection
10. Require real GPU forward.
11. Require zero Vulkan GEMV fallback delta / zero strict violation.
12. Compare the built-in Deep2 per-position checkpoint traces to localize
    drift through embedding, norm, Q/K/V, RoPE, attention, FFN, final norm,
    logits, per-layer checkpoints and KV writes where the production path emits them.
13. Always write a receipt.

This is a REAL model test. There is no generated GGUF fixture in this package.

## Architecture coverage

The harness itself is architecture-agnostic. It calls the current Deep2 public
primitive path, so it can test every architecture that the engine can actually
load and forward:

- Llama / Mistral / Phi families
- Qwen2 / Qwen3
- Gemma / Gemma2 / Gemma3
- MLA / DeepSeek families currently wired
- MoE families currently wired
- Qwen3-Next / Qwen3.5 recurrent models after installing the architecture pack
- Nemotron-H / Mamba2 after installing the architecture pack
- future architectures without modifying this harness

Unsupported architecture graphs still fail model load/forward; the parity harness
does not turn unsupported graphs into fake PASSes.

## Important meaning of "reference"

CPU-vs-Vulkan parity is an **independent backend parity check**, not an external
architecture-definition oracle: both sides intentionally share Deep2's
architecture-level graph.

For full independent architecture truth the same executable also supports a
portable golden file.

### Independent golden mode

`RAWRPARITYG01` contains:

- model SHA-256 and byte size
- architecture
- prompt and prompt token IDs
- per-step teacher/input token
- expected greedy token
- **complete FP32 vocabulary logit vector**

An independently implemented oracle may write this documented little-endian
format. RawrXD can then verify it with no dependency on that oracle:

```powershell
rawrxd_real_gguf_parity.exe `
  --model D:\models\model.gguf `
  --golden D:\cert\independent.rpg `
  --verify-golden `
  --receipt D:\cert\receipt.txt
```

That mode completely skips Deep2 CPU reference generation and compares strict
Vulkan directly to externally supplied full logits.

## Install

```powershell
Expand-Archive .\rawrxd_real_gguf_parity_RAWRXD_REAL_GGUF_PARITY_001.zip `
  -DestinationPath F:\~dev\parity_drop -Force

Set-Location F:\~dev\parity_drop\rawrxd_real_gguf_parity

.\apply_rawrxd_real_gguf_parity.ps1 -RepoRoot "F:\~dev\rawrxd"
```

Build:

```powershell
cmake --build F:\~dev\rawrxd\win32ide_strict\build_v4 `
  --config Release `
  --target rawrxd_real_gguf_parity
```

If that build tree was configured before the target was added, reconfigure the
existing tree once and build the target normally.

## Run one real model

```powershell
$exe="F:\~dev\rawrxd\win32ide_strict\build_v4\Release\rawrxd_real_gguf_parity.exe"

& $exe `
  --model "D:\rawrxd\llama3.2-3b-Q2_K.gguf" `
  --prompt "The meaning of life is" `
  --steps 8 `
  --receipt "F:\cert\llama32_real_parity.txt" `
  --cpu-trace "F:\cert\llama32_cpu.trace" `
  --gpu-trace "F:\cert\llama32_gpu.trace"
```

## Run every GGUF under a model root

```powershell
& "F:\~dev\rawrxd\tools\run_real_gguf_parity_matrix.ps1" `
  -Exe $exe `
  -ModelsRoot "G:\OllamaModels" `
  -OutDir "F:\cert\real_gguf_matrix" `
  -Steps 8
```

This is intentionally explicit; it will load every `.gguf` recursively, so do
not point it at a giant model archive unless you actually want the full matrix.

## Default strict thresholds

- `max_abs <= 5e-3`
- `max_rel <= 5e-3`
- `RMS <= 1e-3`
- `cosine >= 0.99999`
- exact greedy top-1 token
- real GPU forward required
- zero fallback required

Override only when a model/quantization has a documented numerical reason:

```text
--abs X --rel X --rms X --cosine X
```

Use `--topk-exact` if you also want the entire top-K token set to match.

## Golden capture

To preserve the CPU reference for later replays:

```powershell
& $exe --model model.gguf --steps 8 `
  --golden model.rpg --write-golden `
  --receipt capture_and_gpu_verify.txt
```

Model SHA-256 is embedded in the golden. A golden cannot be replayed against a
different GGUF without failing `MODEL_ID`.

## Receipt PASS means

A normal cross-backend PASS requires:

```text
CPU_REFERENCE=PASS
GPU_REPLAY=PASS
TOKEN_PARITY=PASS
LOGIT_PARITY=PASS
REAL_GPU_FORWARD=PASS
GPU_FALLBACK_DELTA=0
GPU_STRICT_VIOLATION=0
CHECKPOINT_TRACE=PASS
VERDICT=PASS
```

The per-step receipt also records CPU/GPU top-1, max abs, mean abs, RMS, max
relative error, cosine and top-K intersection.

## What this intentionally does not fake

This package does not claim:

- an architecture is correct merely because CPU and GPU agree;
- unsupported GPT-OSS/Laguna/DeepSeek4 graphs are magically complete;
- a CPU recurrent reference path is GPU-native;
- tolerance PASS equals exact bitwise parity.

Use independent golden mode for external architecture truth, and the architecture
pack for missing graph implementations.
