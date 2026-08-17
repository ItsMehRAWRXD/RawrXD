# Kimi K2 1T Integration Analysis

## Model Confirmed
- **Model**: Kimi K2-Instruct-0905 (Moonshot AI)
- **Architecture**: DeepSeek2 / MLA + MoE
- **Total Parameters**: ~1T (384 experts, 32B activated)
- **Checkpoint**: Q4_K_M, 13 shards, ~579 GB total
- **Layers**: 61 (1 dense + 60 MoE)
- **Hidden Dim**: 7168
- **Vocab**: 163,840
- **Context**: 262,144
- **Experts**: 384 total, 8 selected/token, 1 shared
- **Expert Dim**: 2048

---

## Tensor Inventory (Shard 0 - 98 tensors)

### Embedding / Output
| Tensor | Type | Shape | Size |
|--------|------|-------|------|
| token_embd.weight | Q4_K | [7168, 163840] | ~661 MB |
| output.weight | Q6_K | [7168, 163840] | ~963 MB |
| output_norm.weight | F32 | [7168] | ~28 KB |

### Dense Layer (blk.0 only)
| Tensor | Type | Shape | Size |
|--------|------|-------|------|
| ffn_down.weight | Q6_K | [18432, 7168] | ~108 MB |
| ffn_gate.weight | Q4_K | [7168, 18432] | ~74 MB |
| ffn_up.weight | Q4_K | [7168, 18432] | ~74 MB |

### MLA Attention (per layer)
| Tensor | Type | Shape | Purpose |
|--------|------|-------|---------|
| attn_q_a.weight | Q4_K | [7168, 1536] | Compress hidden→latent Q |
| attn_q_a_norm.weight | F32 | [1536] | RMS norm on latent Q |
| attn_q_b.weight | Q4_K | [1536, 12288] | Latent→Q heads |
| attn_kv_a_mqa.weight | Q8_0 | [7168, 576] | Compress hidden→latent KV |
| attn_kv_a_norm.weight | F32 | [512] | RMS norm on latent KV |
| attn_k_b.weight | Q8_0 | [128, 512, 64] | K decomposition B |
| attn_v_b.weight | Q8_0 | [512, 128, 64] | V decomposition B |
| attn_output.weight | Q4_K | [8192, 7168] | Output projection |
| attn_norm.weight | F32 | [7168] | Pre-attention RMS norm |

### MoE FFN (blk.1+, per layer)
| Tensor | Type | Shape | Size |
|--------|------|-------|------|
| ffn_gate_inp.weight | F32 | [7168, 384] | Router (~11 MB) |
| ffn_gate_exps.weight | Q4_K | [7168, 2048, 384] | ~3.2 GB |
| ffn_up_exps.weight | Q4_K | [7168, 2048, 384] | ~3.2 GB |
| ffn_down_exps.weight | Q6_K | [2048, 7168, 384] | ~4.6 GB |
| ffn_gate_shexp.weight | Q5_K | [7168, 2048] | Shared gate (~10 MB) |
| ffn_up_shexp.weight | Q5_K | [7168, 2048] | Shared up (~10 MB) |
| ffn_down_shexp.weight | Q6_K | [2048, 7168] | Shared down (~12 MB) |
| exp_probs_b.bias | F32 | [384] | Expert bias (~1.5 KB) |

### Key Insight
**Per MoE layer working set (8 selected experts + shared):**
- Gate: 8 × (7168×2048 Q4_K) ≈ 45 MB
- Up: 8 × (7168×2048 Q4_K) ≈ 45 MB
- Down: 8 × (2048×7168 Q6_K) ≈ 96 MB
- Shared: ~32 MB
- **Total per layer: ~218 MB** (vs ~11.2 GB for all 384 experts)

---

## Integration Gaps Identified

### 1. Deep2 `LayerWeights` Missing MLA Fields
**File**: `src/deep2/Deep2Engine.h`

Current `LayerWeights` has standard attention:
```cpp
WeightTensor wq, wk, wv, wo;  // Standard Q/K/V/O
```

**Missing for DeepSeek2/MLA:**
```cpp
WeightTensor attnQA;        // [hiddenDim, qLoraRank] = [7168, 1536]
WeightTensor attnQANorm;    // [1536]
WeightTensor attnQB;        // [1536, numHeads*headDim] = [1536, 12288]
WeightTensor attnKVA;       // [hiddenDim, kvLoraRank] = [7168, 576]
WeightTensor attnKVANorm;   // [512]
WeightTensor attnKB;        // [128, 512, 64] - K decomposition
WeightTensor attnVB;        // [512, 128, 64] - V decomposition
```

### 2. GGUFLoader Missing DeepSeek2 Tensor Mapping
**File**: `src/deep2/GGUFLoader.hpp` / implementation

Current loader maps standard Llama names:
- `attn_q.weight` → `wq`
- `attn_k.weight` → `wk`
- `attn_v.weight` → `wv`

**Needs DeepSeek2 name mapping:**
- `attn_q_a.weight` → `attnQA`
- `attn_q_b.weight` → `attnQB`
- `attn_kv_a_mqa.weight` → `attnKVA`
- `attn_k_b.weight` → `attnKB`
- `attn_v_b.weight` → `attnVB`
- `ffn_gate_exps.weight` → `moeGate` (3D tensor)
- `ffn_up_exps.weight` → `moeUp` (3D tensor)
- `ffn_down_exps.weight` → `moeDown` (3D tensor)
- `ffn_gate_shexp.weight` → `moeSharedGate`
- `ffn_up_shexp.weight` → `moeSharedUp`
- `ffn_down_shexp.weight` → `moeSharedDown`
- `ffn_gate_inp.weight` → `moeRouter`
- `exp_probs_b.bias` → `moeRouterBias`

### 3. RawrXDTransformer Missing MLA Execution Path
**File**: `src/rawrxd_transformer.cpp`

Current `ExecuteLayerMatMul` handles:
```cpp
// Standard attention
ExecuteLayerMatMul("attn_q.weight", ...)  // Q projection
ExecuteLayerMatMul("attn_k.weight", ...)  // K projection
ExecuteLayerMatMul("attn_v.weight", ...)  // V projection
ExecuteLayerMatMul("attn_o.weight", ...)  // Output projection
```

**Needs MLA path:**
```cpp
// MLA Q path: hidden → attn_q_a → norm → attn_q_b → Q heads
ExecuteLayerMatMul("attn_q_a.weight", hidden, latentQ, ...)
RMSNorm(latentQ, attn_q_a_norm.weight)
ExecuteLayerMatMul("attn_q_b.weight", latentQ, qHeads, ...)

// MLA KV path: hidden → attn_kv_a_mqa → norm → attn_k_b / attn_v_b
ExecuteLayerMatMul("attn_kv_a_mqa.weight", hidden, latentKV, ...)
RMSNorm(latentKV, attn_kv_a_norm.weight)
ExecuteLayerMatMul("attn_k_b.weight", latentKV, kHeads, ...)
ExecuteLayerMatMul("attn_v_b.weight", latentKV, vHeads, ...)
```

### 4. ElasticGGUFIndex Missing DeepSeek2 Block Detection
**File**: `src/runtime/elastic/ElasticGGUFIndex.cpp`

Current `BuildIndexFromTensors()` detects architecture from tensor names.

**Needs to recognize:**
- `deepseek2` architecture (not `llama` or `qwen`)
- `blk.0` is dense FFN (no `_exps` tensors)
- `blk.1+` is MoE (has `_exps`, `_shexp`, `_inp` tensors)
- MLA attention has different residency pattern than standard attention

### 5. MoE Expert Selection Needs `exp_probs_b.bias`
**File**: `src/rawrxd_transformer.cpp` (tryPickMoERouterExperts)

Current code uses:
```cpp
ExecuteLayerMatMul("ffn_gate_inp.weight", ffnNormedHidden, logits, ...)
```

**Needs bias addition:**
```cpp
ExecuteLayerMatMul("ffn_gate_inp.weight", ffnNormedHidden, logits, ...)
// Add exp_probs_b.bias
for (int i = 0; i < nExp; i++) logits[i] += exp_probs_b.bias[i];
```

### 6. Multi-Shard Tensor Namespace
**File**: `src/runtime/elastic/ElasticGGUFIndex.hpp`

Current `ElasticGGUFIndex` wraps a single `GGUFTensorLoader`.

**Needs:**
- Global tensor name → (shard_index, local_tensor_index) mapping
- Shard 0 has 98 tensors, but the complete model has 1,096 tensors across 13 shards
- The `output.weight` and `token_embd.weight` are in shard 0
- Expert weights may be split across shards

---

## Recommended Integration Order

### Phase 1: GGUFLoader DeepSeek2 Support
1. Add DeepSeek2 tensor name mapping to `GGUFLoader`
2. Add MLA fields to `LayerWeights`
3. Parse `deepseek2.*` metadata (q_lora_rank, kv_lora_rank, etc.)
4. Handle 3D expert tensors (`ffn_*_exps.weight`)

### Phase 2: RawrXDTransformer MLA Path
1. Add MLA attention execution in transformer forward
2. Add `exp_probs_b.bias` to MoE router
3. Wire `ElasticEngine` into `ExecuteLayerMatMul`

### Phase 3: Elastic Residency for MoE
1. Update `ElasticGGUFIndex` for DeepSeek2 block detection
2. Implement per-expert residency (stream 8 of 384)
3. Constrain working set to 4-8 GB
4. Measure and report residency metrics

### Phase 4: Multi-Shard Support
1. Extend `ElasticGGUFIndex` for 13-shard namespace
2. Handle cross-shard tensor references
3. Validate complete 1,096 tensor inventory

---

## Files Requiring Changes

| File | Changes Needed |
|------|---------------|
| `src/deep2/Deep2Engine.h` | Add MLA weight fields to `LayerWeights` |
| `src/deep2/GGUFLoader.hpp` | Add DeepSeek2 tensor name mapping |
| `src/deep2/GGUFLoader.cpp` | Implement DeepSeek2/MLA parsing |
| `src/rawrxd_transformer.cpp` | Add MLA attention forward path |
| `src/rawrxd_transformer.h` | Add MLA state variables |
| `src/runtime/elastic/ElasticGGUFIndex.cpp` | DeepSeek2 block detection |
| `src/runtime/elastic/ElasticGGUFIndex.hpp` | Multi-shard support |
| `src/runtime/elastic/ElasticEngine.cpp` | MLA/MoE residency policy |
| `src/runtime/elastic/ElasticResidencyManager.cpp` | Per-expert eviction |
| `src/runtime/TensorExecutionRouter.cpp` | DeepSeek2 kernel dispatch |

---

## Streaming Architecture Target

```
Kimi K2 1T Q4_K_M (579 GB, 13 shards)
           │
           ▼
    ElasticGGUFIndex (multi-shard)
           │
           ▼
    Moon Engine (model graph)
    - Detect deepseek2 arch
    - Schedule MLA + MoE
    - Select 8/384 experts
           │
           ▼
    Elastic Residency Manager
    ┌────────┴────────┐
    │                 │
 4-8 GB window    CPU mmap
 (GPU VRAM)     (NVMe-backed)
    │                 │
    └────────┬────────┘
             ▼
    TensorExecutionRouter
    - Vulkan GEMM (GPU)
    - AVX512 fallback (CPU)
             │
             ▼
         Output logits
```

**Key claim**: Execute 1T-parameter model with ~4-8 GB active weight residency.
