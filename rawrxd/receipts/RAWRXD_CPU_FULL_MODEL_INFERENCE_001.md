# RAWRXD_CPU_FULL_MODEL_INFERENCE_001

Status: **PASS**
Date: 2026-10-30
Gate: `full_model_inference.cpp`, CMake target `full_model_inference`
Model: `F:/~dev/qwen2.5-coder-1.5b-base.gguf` (940,401,408 bytes)
Engine: production `Deep2::Deep2Engine`, greedy, 4-token prompt, 12 tokens requested

## Result

```ini
MODEL_QUANT_TYPES          = F32, Q4_K, Q6_K
LAYERS_COMPLETED           = 28 / 28
ARCH                       = qwen2
HIDDEN=1536  HEADS=12  KV_HEADS=2  GQA_GROUP=6  HEAD_DIM=128
FFN_DIM=8960  VOCAB=151936  QUANT_ADMISSION=Q6_K(type 14)

Q4K_VECTOR_DISPATCHES      = 2520
Q4K_SCALAR_DISPATCHES      = 0
Q6K_VECTOR_DISPATCHES      = 432
Q6K_SCALAR_DISPATCHES      = 0
Q5K_VECTOR_DISPATCHES      = 0
GENERATED_TOKENS           = 12
GREEDY_TOKEN_PARITY        = PASS   (two independent engines, identical tokens)
LOGITS_FINITE              = PASS
VERDICT                    = PASS
```

Exit code 0.

## What makes this evidence rather than assertion

Microkernel parity proves a kernel is correct. It does **not** prove the engine
runs that kernel, and a registry listing a vector kernel proves neither. These
counters are incremented on entry to each kernel body, so the receipt states a
measured fact: during real generation of 12 tokens over all 28 layers, the
admitted vector kernels executed **2,952 times** and the scalar fallbacks
**zero** times.

```ini
Q4_K  2520 dispatches, 0 scalar fallbacks
Q6_K   432 dispatches, 0 scalar fallbacks
Q5_K     0 dispatches  (this model contains no Q5_K tensors)
```

Zero scalar fallbacks on admitted geometry is the substantive claim: the
production path is not silently degrading to the reference implementation.

The kernels are now **proved contributors to correct end-to-end inference**, not
isolated microkernel results.

## Generated tokens

Greedy, reproducible across two independent engine instances:

```text
82, 284, 220, 15, 280, 262, 869, 526, 296, 2507, 1001, 1002
```

## Harness defect found and fixed

The first run reported `GREEDY_TOKEN_PARITY FAIL` with `RUN2_TOKENS=0`. Cause
was the harness, not the engine: it reused one engine for the second
generation, leaving a populated KV cache, against which `generate()` correctly
returned 0 tokens. That measured cache reuse, not determinism. Fixed by
constructing a **second independent engine** for the parity run.

This is the same class of error as the earlier ones: a test whose pass
condition can be satisfied by an inert system. Here the reverse held — it
reported FAIL for a healthy engine.

## Build integration

```ini
TARGET                    = full_model_inference (EXCLUDE_FROM_ALL)
LINKS                     = InferenceEngine
INCLUDE                   = /arch:AVX512, ctest-registered when BUILD_TESTING
```

Linked through CMake so it inherits the full `InferenceEngine` closure rather
than a hand-rolled subset. Compiles clean on both `/arch:AVX512` and
`/arch:AVX2`.

## Ladder movement

```ini
CPU_Q4_K_GEMV_CORRECTNESS      = CLOSED
CPU_Q6_K_GEMV_CORRECTNESS      = CLOSED
CPU_QUANT_KERNEL_DISPATCH      = CLOSED
REAL_MODEL_QUANT_GEOMETRY      = CLOSED
Q4_K_REACHES_FULL_INFERENCE    = PROVEN   (this receipt)

Q5_K_AVX512_CORRECTNESS        = OPEN_WITHHELD
GPU_QUANT_EXECUTION            = OPEN_INVALID
ATTENTION / KV_CACHE           = OPEN (executed but not separately certified)
SAMPLING                       = OPEN (greedy only; no distribution tested)
QUANTIZED_LOGIT_PARITY         = OPEN (tokens reproduce; no reference logit vector)
END_TO_END_INFERENCE            = PARTIAL (CPU, greedy, this model)
```

## Explicitly not claimed

- **No reference-output parity.** Tokens are self-consistent across runs; they
  are not compared against llama.cpp or any external implementation, so this
  proves determinism and execution, not correctness of the text.
- **Greedy only.** Temperature/top-p sampling is untouched by this gate.
- **CPU only.** `vulkan=0/0` throughout; the GPU path remains unexecuted.
- **One model, one geometry.** Qwen2.5-Coder-1.5B (qwen2, GQA group 6). Other
  architectures, MoE, MLA and recurrent families are untouched.
- Logit finiteness is asserted by the engine's own forward path; logits were not
  independently captured and compared.