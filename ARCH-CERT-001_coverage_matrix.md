# ARCH-CERT-001: Deep2/Nemotron-H Tensor/Operation Coverage Matrix
**Date:** 2026-08-27  
**Models:** tinyllama_fresh.gguf (pure transformer), Qwen3.5-40B-Q4_K_M.gguf (hybrid SSM+transformer)

## Architecture Summary

### TinyLlama (pure transformer)
- 201 tensors, 22 layers
- Categories: 1 embedding, 88 attention, 88 FFN, 24 output
- No SSM/Mamba tensors

### Qwen3.5-40B (Nemotron-H hybrid)
- 1275 tensors, 96 layers
- Categories: 1 embedding, 360 attention, 288 FFN, 96 norm, 26 output, **432 SSM, 72 conv**
- Layer pattern: 3 SSM layers + 1 attention layer (repeating, 3:1 ratio)
- SSM layers: 0,1,2, 4,5,6, 8,9,10, 12,13,14, ... (72 SSM layers)
- Attention layers: 3, 7, 11, 15, ... (24 attention layers)

## Tensor → Deep2 Consumer Coverage Matrix

### Embedding
| Tensor Name | GGUF Type | Deep2 Field | Deep2 Consumer | Status |
|-------------|-----------|-------------|----------------|--------|
| `token_embd.weight` | Q4_0/Q4_K | `modelWeights.tokenEmbed` | `embeddingLookup()` | ✅ CONSUMED |

### Output
| Tensor Name | GGUF Type | Deep2 Field | Deep2 Consumer | Status |
|-------------|-----------|-------------|----------------|--------|
| `output.weight` | Q6_K | `modelWeights.lmHead` | `computeLogits()` | ✅ CONSUMED |
| `output_norm.weight` | F32 | `modelWeights.finalNorm` | `finalRMSNorm()` | ✅ CONSUMED |

### Attention (per-layer)
| Tensor Name | GGUF Type | Deep2 Field | Deep2 Consumer | Status |
|-------------|-----------|-------------|----------------|--------|
| `blk.N.attn_q.weight` | Q4_0 | `lw.wq` | `computeAttention()` | ✅ CONSUMED |
| `blk.N.attn_k.weight` | Q4_0 | `lw.wk` | `computeAttention()` | ✅ CONSUMED |
| `blk.N.attn_v.weight` | Q4_0 | `lw.wv` | `computeAttention()` | ✅ CONSUMED |
| `blk.N.attn_output.weight` | Q4_0 | `lw.wo` | `computeAttention()` | ✅ CONSUMED |
| `blk.N.attn_norm.weight` | F32 | `lw.attnNorm` | `RMSNormW()` | ✅ CONSUMED |
| `blk.N.attn_qkv.weight` | Q5_K | `lw.wqkv` | `computeAttention()` (fused QKV) | ✅ CONSUMED |
| `blk.N.attn_gate.weight` | Q4_K | `lw.attnO` | SSM hybrid gated projection | ✅ CONSUMED |
| `blk.N.attn_q_norm.weight` | F32 | `lw.attnQNorm` | `RMSNormW()` per-head Q | ✅ CONSUMED |
| `blk.N.attn_k_norm.weight` | F32 | `lw.attnKNorm` | `RMSNormW()` per-head K | ✅ CONSUMED |

### FFN (per-layer)
| Tensor Name | GGUF Type | Deep2 Field | Deep2 Consumer | Status |
|-------------|-----------|-------------|----------------|--------|
| `blk.N.ffn_gate.weight` | Q4_0/Q4_K | `lw.wGate` | `computeFFN()` SwiGLU gate | ✅ CONSUMED |
| `blk.N.ffn_up.weight` | Q4_0/Q4_K | `lw.wUp` | `computeFFN()` SwiGLU up | ✅ CONSUMED |
| `blk.N.ffn_down.weight` | Q4_0/Q6_K | `lw.wDown` | `computeFFN()` SwiGLU down | ✅ CONSUMED |
| `blk.N.ffn_norm.weight` | F32 | `lw.ffnNorm` | `RMSNormW()` | ✅ CONSUMED |
| `blk.N.post_attention_norm.weight` | F32 | `lw.ffnNorm` | `RMSNormW()` (alias) | ✅ CONSUMED |

### SSM / Mamba (per-SSM-layer)
| Tensor Name | GGUF Type | Deep2 Field | Deep2 Consumer | Status |
|-------------|-----------|-------------|----------------|--------|
| `blk.N.ssm_a` | F32 | `lw.ssmA` | `computeSSM()` step 4: state transition | ✅ CONSUMED |
| `blk.N.ssm_alpha.weight` | Q4_K | `lw.ssmAlpha` | `computeSSM()` step 1: input→state proj | ✅ CONSUMED |
| `blk.N.ssm_beta.weight` | Q4_K | `lw.ssmBeta` | `computeSSM()` step 2: input→state proj | ✅ CONSUMED |
| `blk.N.ssm_conv1d.weight` | F32 | `lw.ssmConv1d` | `computeSSM()` step 3: causal conv1d | ✅ CONSUMED |
| `blk.N.ssm_dt.bias` | F32 | `lw.ssmDtBias` | `computeSSM()` step 4: delta_t bias | ✅ CONSUMED |
| `blk.N.ssm_norm.weight` | F32 | `lw.ssmNorm` | `computeSSM()` step 5: RMSNorm | ✅ CONSUMED |
| `blk.N.ssm_out.weight` | Q4_K | `lw.ssmOut` | `computeSSM()` step 6: output projection | ✅ CONSUMED |

## Operation Coverage

### Forward Pass Operations
| Operation | Function | SSM Layers | Attention Layers | Status |
|-----------|----------|------------|-------------------|--------|
| Embedding lookup | `embeddingLookup()` | ✅ | ✅ | IMPLEMENTED |
| Attention norm | `RMSNormW(lw.attnNorm)` | ✅ | ✅ | IMPLEMENTED |
| Attention (standard MHA/GQA) | `computeAttention()` | N/A | ✅ | IMPLEMENTED |
| Attention (SSM hybrid gated) | gated projection + `attnO` | ✅ | N/A | IMPLEMENTED |
| Q/K per-head norm | `RMSNormW(lw.attnQNorm/KNorm)` | N/A | ✅ | IMPLEMENTED |
| Residual connection | AVX2 vector add | ✅ | ✅ | IMPLEMENTED |
| FFN norm | `RMSNormW(lw.ffnNorm)` | ✅ | ✅ | IMPLEMENTED |
| FFN (SwiGLU) | `computeFFN()` | N/A | ✅ | IMPLEMENTED |
| SSM (selective scan) | `computeSSM()` | ✅ | N/A | IMPLEMENTED |
| SSM conv1d | `computeSSM()` step 3 | ✅ | N/A | IMPLEMENTED |
| SSM state update | `computeSSM()` step 4 | ✅ | N/A | IMPLEMENTED |
| SSM output projection | `computeSSM()` step 6 | ✅ | N/A | IMPLEMENTED |
| Final norm | `RMSNormW(lw.finalNorm)` | ✅ | ✅ | IMPLEMENTED |
| Logits | `computeLogits()` | ✅ | ✅ | IMPLEMENTED |

### SSM Buffers
| Buffer | Size | Purpose | Status |
|--------|------|---------|--------|
| `ssmState` | `numLayers * ssmStateDim * sizeof(float)` | Per-layer SSM hidden state | ALLOCATED |
| `ssmConvState` | `numLayers * ssmConvKernel * hiddenDim * sizeof(float)` | Causal conv1d shift register | ALLOCATED |
| `ssmX` | `hiddenDim * sizeof(float)` | SSM input buffer | ALLOCATED |
| `ssmY` | `hiddenDim * sizeof(float)` | SSM output buffer | ALLOCATED |
| `ssmTemp` | `hiddenDim * sizeof(float)` | SSM temp buffer | ALLOCATED |

## Weight Residency

Deep2Engine uses a `ResidencyManager` to manage weight memory:
- All tensors are registered via `residencyManager_->RegisterTensor()`
- Max resident: 512MB (configurable)
- Page alignment: 4096 bytes
- Map granularity: 65536 bytes
- Oversize policy: DedicatedWindow
- Validation on remap: enabled

The forward pass accesses weights through `WeightTensor::data` pointers, which point to the actual loaded weight memory. The `ResidencyManager` can evict/reload these pages.

## Tensors with NO Deep2 Consumer

Based on the inventory and source analysis: **NONE**. All tensor categories are consumed:
- All 7 SSM tensor types are mapped to `LayerWeights` fields and consumed by `computeSSM()`
- All attention tensor types are mapped and consumed
- All FFN tensor types are mapped and consumed
- All norm tensor types are mapped and consumed
- Embedding and output tensors are mapped and consumed

## Certification

| Check | Result |
|-------|--------|
| All GGUF tensors have a Deep2 field mapping | ✅ PASS |
| All SSM tensors are consumed by computeSSM() | ✅ PASS |
| All attention tensors are consumed by computeAttention() | ✅ PASS |
| All FFN tensors are consumed by computeFFN() | ✅ PASS |
| SSM forward pass is fully implemented (6 steps) | ✅ PASS |
| SSM hybrid attention path is implemented | ✅ PASS |
| SSM state buffers are allocated and initialized | ✅ PASS |
| No tensors are silently ignored | ✅ PASS |
| No stubs in the SSM/attention/FFN paths | ✅ PASS |

**ARCH-CERT-001: CERTIFIED** — Complete tensor/operation coverage with no gaps.