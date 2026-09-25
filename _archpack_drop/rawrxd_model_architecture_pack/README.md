# RAWRXD_MODEL_ARCH_PACK_001

Source-only / no new dependencies.

This pack targets the architecture gap visible on RawrXD `master` after commit
`22dc2775`: Deep2 has generic MHA/GQA, Q/K norm, MoE, MLA and declared SSM
storage, but the production `computeSSM()` path still fails closed because no
real recurrent provider is bound.

## What the pack adds

### Central architecture authority

Recognizes and classifies:

- llama
- mistral
- phi3
- qwen / qwen2 / qwen2moe
- qwen3 / qwen3moe
- qwen3next
- qwen35 / qwen35moe
- gemma / gemma2 / gemma3
- deepseek2 / deepseek32 / deepseek4
- nemotron / nemotron_h / nemotron_h_moe
- gpt-oss
- laguna
- mamba / mamba2

Unknown architectures fail admission instead of silently entering Llama math.

### Generic-path architectures

The catalog explicitly marks architectures whose current Deep2 primitive set is
a valid base: Llama/Mistral/Phi3, Qwen2/Qwen3 families, Gemma family, and the
existing DeepSeek MLA path.

### Qwen3-Next / Qwen3.5

Adds a scalar FP32 autoregressive Gated Delta Net reference path:

- QKV(/Z) projection
- depthwise causal conv state
- SiLU
- Q/K L2 norm
- beta sigmoid
- `g = softplus(alpha + dt_bias) * A`
- FP32 recurrent state
- Delta-rule state update
- gated RMS norm
- output projection

The state update follows the autoregressive DeltaNet contract:

`S' = exp(g) * S + k outer [beta * (v - exp(g) * S^T k)]`

This is a correctness/reference path, not a claim of Vulkan throughput parity.

### Nemotron-H / Mamba2

Adds a scalar FP32 autoregressive Mamba2 reference path:

- `ssm_in` projection
- z/x/B/C/dt split
- depthwise causal conv
- selective state update
- skip D
- gated normalization
- output projection

Again: this is a bring-up/reference path. It gives Deep2 a real recurrent
implementation instead of identity/synthetic behavior, but requires model-level
parity certification before promotion to strict production authority.

### Special graphs

`gpt-oss`, `laguna`, and `deepseek4` are recognized explicitly but remain
special-graph architectures. The pack intentionally does NOT alias them to
Llama or generic MoE math. That prevents false success while their model-specific
router/gating/attention graphs are implemented.

## Install

```powershell
Set-Location <unzipped-drop>
.\apply_rawrxd_model_architecture_pack.ps1 -RepoRoot "F:\~dev\rawrxd"
```

The patcher:

1. copies three header-only source files,
2. adds an owned `ArchitectureRuntime` to `Deep2Engine`,
3. recognizes architecture at model load,
4. binds recurrent tensors after GGUF binding,
5. resets recurrent state on conversation reset,
6. dispatches recurrent layers to the architecture runtime,
7. replaces the old deliberately-throwing `computeSSM()` body,
8. refuses ambiguous source edits,
9. makes timestamped backups.

No CMake source-list change is necessary because the implementation is
header-only.

## Self-test

The pure math self-test has no RawrXD dependencies:

```powershell
cl /std:c++20 /EHsc tests\architecture_math_selftest.cpp
.\architecture_math_selftest.exe
```

or:

```bash
c++ -std=c++20 tests/architecture_math_selftest.cpp -o architecture_math_selftest
./architecture_math_selftest
```

Expected:

`RAWRXD_MODEL_ARCH_PACK_001_SELFTEST=PASS`

## Promotion rule

Do not call a newly recognized architecture "supported" merely because it loads.

For each real model family require:

`GGUF -> architecture recognized -> tensors bound -> real forward -> finite logits -> deterministic reference token parity -> multi-token parity`

For recurrent models also require state-reset and long-prompt parity.

## Current special-graph work intentionally NOT faked

The following need separate architecture-specific graph source before strict
parity can be claimed:

- GPT-OSS: model-specific MoE / attention graph and MXFP4 semantics.
- Laguna: sigmoid-routed MoE, score-correction bias, shared expert, attention
  output gating and layer-type-specific RoPE/SWA.
- DeepSeek4: do not alias blindly to DeepSeek2/3 MLA.

The catalog makes these gaps explicit so RawrXD cannot accidentally report a
generic-transformer PASS for them.
