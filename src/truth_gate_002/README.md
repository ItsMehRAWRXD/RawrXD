# RawrXD Truth Gate Validation Chain

This directory contains the truth gate validation system for RawrXD model inference.

## Philosophy

**Truth Gates** are hard validation milestones that prove specific capabilities with measurable evidence. No hand-waving, no "it should work" — only proven execution paths.

## Validation Chain

| Gate | Status | What It Proves |
|------|--------|----------------|
| **Truth Gate 001** | ✅ Complete | Build system, basic execution |
| **Truth Gate 002** | ✅ Prototype Validated | GGUF parsing, tensor extraction, operator primitives |
| **Truth Gate 003** | 📋 Planned | Real model inference with reference validation |

---

## Truth Gate 002 — Current State

### ✅ Proven
- GGUF container ingestion
- Metadata parsing
- Tensor discovery
- Tensor type handling (F32, F16, Q4_0 structure)
- Core primitives (RMSNorm, RoPE, Softmax, Matmul)
- Execution infrastructure

### ⚠️ Not Proven
- Quantized inference on real model weights
- Full transformer layer execution
- KV-cache behavior
- Token generation

### ❌ Not Proven
- Generated tokens from real GGUF model
- Numerical agreement with llama.cpp

**See**: [TRUTH_GATE_002_STATE.md](TRUTH_GATE_002_STATE.md) for complete assessment

---

## Truth Gate 003 — Next Milestone

**Goal**: Generate tokens from real GGUF model with numerical validation against llama.cpp

**Required Models**:
1. tinyllama-1.1b Q4_0 (fast iteration)
2. phi-3-mini Q4_K (complex quantization)

**Pass Conditions**:
- 100% tensor coverage
- Logit agreement within ε=0.01
- Generated tokens match reference
- Performance metrics captured

**See**: `../truth_gate_003/TRUTH_GATE_003_PLAN.md` for implementation plan

---

## Files

| File | Purpose |
|------|---------|
| `tg002_tensor_extract.c` | Phase 1: GGUF parsing |
| `tg002_integrated.c` | Phase 2: F32/F16 dequantization |
| `tg002_dequant_q4.c` | Phase 2b: Q4_0/Q4_K dequantization |
| `tg002_transformer.c` | Phase 3: Transformer primitives |
| `TRUTH_GATE_002_STATE.md` | Current state assessment |
| `TRUTH_GATE_002_HONEST_ASSESSMENT.md` | Detailed reality check |
| `TRUTH_GATE_002_COMPLETE.md` | Milestone summary |

---

## Build

```bash
cd d:\rawrxd\src\truth_gate_002

# Phase 1
gcc -O2 tg002_tensor_extract.c -o tg002_tensor_extract.exe

# Phase 2
gcc -O2 tg002_integrated.c -o tg002_integrated.exe -lm

# Phase 2b
gcc -O2 tg002_dequant_q4.c -o tg002_dequant_q4.exe -lm

# Phase 3
gcc -O2 -Wall tg002_transformer.c -o tg002_transformer.exe -lm
```

---

## Test

```bash
# Requires bench_min.gguf in d:\rawrxd\
./tg002_transformer.exe d:\rawrxd\bench_min.gguf
```

---

**Status**: Truth Gate 002 infrastructure proven. Ready for Truth Gate 003 implementation.
