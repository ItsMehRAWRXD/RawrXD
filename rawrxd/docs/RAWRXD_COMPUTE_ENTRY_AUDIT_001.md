# RAWRXD_COMPUTE_ENTRY_AUDIT_001

## Purpose
Trace every production compute entry point that consumes model weights in Deep2, identify which paths bypass `LinearW()`, collapse the real load/runtime path into one reverse layer, and produce the first kernel-facing cut for the polymorphic sourceless kernel generator.

---

## 1. Complete Compute Entry Census

### 1.1 CPU Paths (via `LinearW`)

| Entry Point | File | Line | Weight Sources | Notes |
|-------------|------|------|----------------|-------|
| `LinearW()` | Deep2Engine.cpp | 3853 | All `WeightTensor` via `wt.data` | Primary CPU GEMV dispatch |
| `LinearW()` EV overload | Deep2Engine.cpp | 4010 | All via `ExecutionView` | Pilot: F32 only, delegates to legacy |
| `LinearWBatch4()` | Deep2Engine.cpp | 5245 | `modelWeights.lmHead` (Q4_K only) | Batched logits, dual-GPU only |
| `forwardTokenAllLayers()` | Deep2Engine.cpp | 5699 | All layers via `forwardLayer` | Orchestrates CPU/GPU hybrid |

**Every CPU kernel path goes through `LinearW()`** — there are no direct tensor accesses in CPU forward.

### 1.2 GPU Paths (bypass `LinearW`)

| Entry Point | File | Line | Weight Sources | Mechanism |
|-------------|------|------|----------------|-----------|
| `tryVulkanHostGEMV()` | Deep2Engine_GpuMoEMLA.cpp | 67 | Any `WeightTensor` via `wt.data` | Single GPU: `DispatchWeight()` |
| `tryVulkanHostGEMVGroup()` | Deep2Engine_GpuMoEMLA.cpp | 166 | Q/K/V triple via `wt.data` | Dual-GPU row split: `Deep2RunDualGpuRowSplitGroup()` |
| `tryVulkanHostGEMVBatch4()` | Deep2Engine_GpuMoEMLA.cpp | 142 | `lmHead` (Q4_K only) | Dual-GPU row split batch |
| `computeMoEFFNGpu()` | Deep2Engine_GpuMoEMLA.cpp | 193 | Router + expert gate/up/down | `RunExpertFFN()` per expert |
| `forwardLayerGpuResident()` | Deep2Engine_GpuForward.cpp | 1330 | All layer weights via `wt.data` | Fully resident: `DispatchGemvQuant()` / `DispatchGemvDevice()` |
| `computeMLAAttentionGpu()` | Deep2Engine_GpuMoEMLA.cpp | 324 | 8 MLA tensors via `tryVulkanHostGEMV` | Host-staged projections + `RunMLAAttentionHost()` |
| `forwardTokenGpuHybrid()` | Deep2Engine_GpuMoEMLA.cpp | 430 | Delegates to `forwardLayer()` (CPU) | Host orchestration, not resident |

### 1.3 Specialized Paths

| Entry Point | File | Line | Weight Sources |
|-------------|------|------|----------------|
| `projectionBisectRun()` | Deep2Engine_GpuForward.cpp | 905 | Q/K/V via `LinearW()` + `EnsureF32()` |
| `postVChainReplay()` | Deep2Engine_GpuForward.cpp | 1115 | All via `LinearW()` on captured vectors |
| `ropeBisectRun()` | Deep2Engine_GpuForward.cpp | 1247 | Captured pre/post-RoPE only |

---

## 2. Direct Weight Access Sites (No `LinearW`)

These are the **only** sites in the production tree that read `wt.data` without going through `LinearW()`:

### 2.1 Vulkan Dispatch Layer

```cpp
// Deep2Engine_GpuMoEMLA.cpp:89-139 — tryVulkanHostGEMV (single GPU)
GpuWeightView view{};
if (!fullView(wt, view)) return false;  // wt.data → GpuWeightView
auto& x = g->Scratch(30);
auto& y = g->Scratch(31);
g->UploadVector(x, input, wt.cols);
g->DispatchWeight(view, x, y);  // wt.data consumed HERE
g->DownloadVector(y, output, wt.rows);
```

```cpp
// Deep2Engine_GpuMoEMLA.cpp:166-191 — tryVulkanHostGEMVGroup (dual GPU)
RowSplitReceipt r{};
Deep2RunDualGpuRowSplitGroup(
    *vulkanDevices_[0], *vulkanDevices_[1],
    weights, outputs, count, input, inputCount, epoch, &r);
// weights[i]->data consumed in Deep2DualGpuRowSplit
```

```cpp
// Deep2Engine_GpuForward.cpp:1490-1558 — gemv lambda (resident path)
if (PackedQuant(wt)) {
    bool r = vc->DispatchGemvQuant(wt.type, wt.data, wt.sizeBytes,
                                    in, out, rows, cols);
    // wt.data consumed HERE — packed quant path
} else {
    const float* w = EnsureF32(*this, wt, vulkanWeightF32_);
    // F32 expansion path
    r = vc->DispatchGemvDevice(w, WeightKey(wt), in, out, rows, cols);
}
```

### 2.2 Prepared Weight Cache (CPU F32 expansion)

```cpp
// Deep2Engine_GpuForward.cpp:239-265 — EnsureF32
Deep2::PreparedWeightSource src;
src.data = reinterpret_cast<const uint8_t*>(wt.data);  // wt.data read HERE
src.sizeBytes = wt.sizeBytes;
auto deq = QuantKernelRegistry::Instance().GetDequant(wt.type);
return e.PreparedWeights().Acquire(src, deq);  // dequantizes wt.data → F32
```

### 2.3 Dual GPU Row Split

```cpp
// Deep2DualGpuRowSplit.cpp:146, 233, 240, 736, 761
// wt.data used as:
// - cache key (unordered_map keyed by wt.data pointer)
// - source pointer for memcpy into device staging
// - byte offset calculation for row slicing
```

### 2.4 Identity Checks (not compute)

```cpp
// Deep2Engine.cpp:3893
const bool isLmHead = (&wt == &modelWeights.lmHead);  // pointer identity only

// Deep2Engine.cpp:4019
ev.transientAddress = wt.data;  // ExecutionView bridge (baseline, no residency change)
```

---

## 3. Load → Runtime Path Collapse (Reverse Layer)

### 3.1 GGUF Load Path (measured)

```
GGUFLoader::load(path)
    │
    ▼
loader.getTensor(name) → GGUFTensor* { data, sizeBytes, shardId, fileOffset, shape, type }
    │
    ▼
bindTensor(name, WeightTensor& wt)
    │
    ├── wt.data = const_cast<uint8_t*>(t->data)           ← ALIAS into mmap
    ├── wt.sizeBytes = t->sizeBytes
    ├── wt.type = t->type
    ├── wt.shape = t->shape
    ├── wt.mapped = true
    ├── wt.shardId = t->shardId
    ├── wt.fileOffset = t->fileOffset
    ├── wt.hasFileBacking = true
    └── wt.rows/cols derived from shape
    │
    ▼
ModelWeights.layers[layer].{wq,wk,wv,wo,wqkv,wGate,wUp,wDown,...}
    │
    ▼
ggufResult.loader = loader  ← LOADER RETAINED so mmap stays valid
ggufResult.mmapBound = 1
```

**Critical invariant:** `wt.data` is an **alias into the GGUF mmap**, not an independent allocation. The loader is retained in `ggufResult.loader` specifically to keep the mapping alive.

### 3.2 Runtime Resolution Path

```
Execution requires tensor T
    │
    ▼
TensorIdentity { model, layer, role, expert, variant }
    │
    ▼
Resolver.resolve(TensorIdentity)
    │
    ├── CPU path: wt.data (alias) → LinearW() → kernel(wt.data)
    │
    ├── GPU single: wt.data → fullView() → GpuWeightView → DispatchWeight()
    │
    ├── GPU dual row split: wt.data → Deep2RunDualGpuRowSplit() → device
    │
    ├── GPU resident: wt.data → DispatchGemvQuant(wt.data) / DispatchGemvDevice(F32)
    │
    └── GPU MLA: wt.data → tryVulkanHostGEMV() → host staging → RunMLAAttentionHost()
```

---

## 4. Reverse Layer: NanoAddress

### 4.1 The Contract

```cpp
// NanoAddress — the addressless execution request
// Generated by Reverse from KernelIntent + Heartbeat/Beacon
struct NanoAddress {
    KernelIdentity    identity;      // WHAT computation
    ExecutionConstraints constraints; // WHERE/WHEN it must execute
    BackingRef        backing;       // HOW to recover bytes (NOT an address)
    LeaseToken        lease;         // Validity window
};
```

### 4.2 Reverse Transformation

```
KernelIntent (semantic)
    │
    ▼
REVERSE LAYER
    │
    ├─ Decompose operation → primitive graph (LOAD, DEQUANT, DOT, REDUCE, ...)
    │
    ├─ Resolve identity → BackingRef
    │     ├─ GGUF mmap: { shardId, fileOffset, byteLength, quantType, shape }
    │     ├─ Prepared F32: { cacheKey, generation, bytes }
    │     ├─ GPU resident: { deviceId, allocationId, generation }
    │     └─ Regenerated: { seed, parameters }
    │
    ├─ Query Heartbeat/Beacon for current reality
    │     ├─ Available devices
    │     ├─ VRAM pressure
    │     ├─ Residency map
    │     ├─ Peer reachability
    │     └─ Representation availability
    │
    └─ Emit NanoAddress (no physical address)
```

### 4.3 BackingRef (replaces physical address)

```cpp
struct TensorBackingRef {
    // Source identity — survives representation changes
    uint32_t        shardId;
    uint64_t        fileOffset;
    uint64_t        byteLength;
    uint32_t        quantType;
    TensorShape     shape;

    // Residency hints (ephemeral)
    ResidencyHint   preferredTier;   // VRAM / RAM / mmap / cache
    uint64_t        generation;      // current backing generation
    bool            isPrepared;      // F32 cache valid
    uint32_t        deviceId;        // if GPU resident
};
```

**This replaces `wt.data` everywhere.** The pointer is never exposed outside the resolver.

---

## 5. Kernel-Facing Cut: PolyKernel Generator

### 5.1 Semantic Kernel Identity

```cpp
struct KernelIdentity {
    Operation       operation;       // MatrixVector, RoPE, RMSNorm, Attention, etc.
    NumericContract contract;        // Exact Deep2 Q4_K semantics, F32, etc.
    RepresentationClass representation; // Quantized, F32, packed, etc.
};
```

### 5.2 Primitive Operation Set (composable)

| Primitive | Description | Quant-Aware |
|-----------|-------------|-------------|
| `LOAD_BLOCK` | Load quantized block from backing | Yes (blockBytes, blockElements) |
| `DEQUANT` | Dequantize block → F32 | Per-type |
| `DOT` | Vector dot product | F32 |
| `ACCUMULATE` | F32 accumulator | F32 |
| `STORE` | Write F32 result | F32 |
| `ROPE` | Apply rotary embedding | F32 |
| `RMSNORM` | RMS normalization | F32 weights |
| `SILU` / `GELU` / `GEGLU` | Activations | F32 |
| `SOFTMAX` | Attention softmax | F32 |
| `CACHE_READ` / `CACHE_WRITE` | KV cache access | F32 |

### 5.3 Q4_K GEMV as Primitive Composition

```text
KernelIdentity {
    operation = MatrixVector
    contract = Deep2_Q4_K_GEMV
    representation = Q4_K
}
    │
    ▼
Primitive Graph:
    LOAD_BLOCK (256 elements, 84 bytes)
        │
        ▼
    DEQUANT_Q4_K → F32[256]
        │
        ▼
    DOT (input vector × dequantized block)
        │
        ▼
    ACCUMULATE (per-row)
        │
        ▼
    STORE (output[row])
```

### 5.4 Backend Lowering (same primitives, different forms)

| Backend | LOAD_BLOCK | DEQUANT | DOT | ACCUMULATE |
|---------|------------|---------|-----|------------|
| CPU AVX2 | vmovdqu | scalar/vpdpbusd | vpdpbusd | vpaddd |
| CPU AVX-512 | vmovdqu64 | vpdpbusd + vpmadd | vpdpbusd | vpaddd |
| Vulkan single | subgroupLoad | subgroupDequant | subgroupDot | subgroupReduce |
| Vulkan dual-row | 2× subgroupLoad | 2× subgroupDequant | 2× subgroupDot | hostMerge |
| Vulkan resident | deviceLoad | persistentDequant | deviceDot | deviceReduce |
| Sparse expert | expertLoad | expertDequant | expertDot | expertReduce |

### 5.5 Generation Flow

```
KernelIntent
    │
    ▼
REVERSE (logical decomposition)
    │
    ▼
PrimitiveGraph (semantic, addressless)
    │
    ▼
HEARTBEAT QUERY (current reality)
    │
    ▼
BackendSelector (chooses form for THIS moment)
    │
    ▼
PolyKernelSourceGenerator
    │
    ├─ CPU: emits C++ + intrinsics
    ├─ Vulkan: emits GLSL/SPIR-V
    └─ Hybrid: emits host orchestration + device kernels
    │
    ▼
PolyCompiler (receipt-driven)
    │
    ├── SOURCE_DIGEST = hash(source)
    ├── BEACON_GENERATION = n
    ├── HARDWARE_FINGERPRINT = hash
    ├── COMPILE = PASS
    ├── LINK = PASS
    ├── REFERENCE_PARITY = PASS (vs CPU scalar reference)
    ├── FINITE_OUTPUT = PASS
    ├── EXECUTION_COUNT > 0
    ├── REAL_KERNEL_ENTERED = 1
    └── BINARY_DIGEST = hash(binary)
    │
    ▼
KernelForm { identity, backend, source, binary, beaconGeneration }
    │
    ▼
KernelReceipt (immutable)
    │
    ▼
HOTPATCH BINDING SWAP (not binary mutation)
```

---

## 6. Measurable Gates for First Cut

### Gate 1: Reverse Layer Correctness
```ini
RAWRXD_REVERSE_LAYER_CORRECTNESS_001

TEST: For every WeightTensor in ModelWeights:
  1. Reverse.resolve(identity) → BackingRef
  2. BackingRef resolves to SAME bytes as wt.data
  3. BackingRef.shardId == wt.shardId
  4. BackingRef.fileOffset == wt.fileOffset
  5. BackingRef.quantType == wt.type
  6. BackingRef.shape == wt.shape

VERDICT = PASS iff all 6 hold for every tensor
```

### Gate 2: Primitive Graph Equivalence
```ini
RAWRXD_PRIMITIVE_GRAPH_EQUIVALENCE_001

TEST: Q4_K GEMV primitive graph vs legacy LinearW
  1. Generate primitive graph for Q4_K MatrixVector
  2. Lower to CPU AVX2 form
  3. Execute on 100 random (input, weight) pairs
  4. Compare output bit-for-bit with QuantKernelRegistry::GetGEMV(12)

VERDICT = PASS iff maxAbsDiff == 0 for all 100 pairs
```

### Gate 3: Backend Form Selection
```ini
RAWRXD_BACKEND_FORM_SELECTION_001

TEST: Same KernelIntent, different Heartbeat states
  State A: 2 GPUs available, VRAM 80% free
    → Form = Vulkan dual-row
  State B: 1 GPU, VRAM 95% free
    → Form = Vulkan resident
  State C: 0 GPUs, CPU AVX-512
    → Form = CPU AVX-512
  State D: 0 GPUs, CPU AVX2 only
    → Form = CPU AVX2

VERDICT = PASS iff each form executes and produces identical output
```

### Gate 4: Hotpatch Binding Swap
```ini
RAWRXD_HOTPATCH_BINDING_SWAP_001

TEST: Form A (generation n) → Form B (generation n+1)
  1. Execute 10 tokens with Form A
  2. Simulate VRAM pressure change (Heartbeat generation++)
  3. Generate Form B for same KernelIntent
  4. Swap binding at layer boundary
  5. Execute 10 more tokens
  6. Verify output continuity (no NaN, no divergence at boundary)

VERDICT = PASS iff continuity holds
```

---

## 7. Summary: The Reverse Layer Collapse

### Before (current reality)
```
ModelWeights (monolithic address table)
    │
    ├─ LinearW() → wt.data → scalar kernels
    ├─ tryVulkanHostGEMV() → wt.data → DispatchWeight()
    ├─ tryVulkanHostGEMVGroup() → wt.data → Deep2RunDualGpuRowSplit()
    ├─ forwardLayerGpuResident() → wt.data → DispatchGemvQuant()
    └─ computeMLAAttentionGpu() → wt.data → tryVulkanHostGEMV() → RunMLAAttentionHost()
```

### After (reverse layer + polymorphic generator)
```
KernelIntent (semantic requirement)
    │
    ▼
REVERSE LAYER
    │
    ├─ Logical decomposition → PrimitiveGraph
    │
    ├─ Identity → BackingRef (shardId, fileOffset, quantType, shape)
    │
    └─ Heartbeat query → ExecutionReality
    │
    ▼
POLYKERNEL GENERATOR
    │
    ├─ CPU AVX2 form
    ├─ CPU AVX-512 form
    ├─ Vulkan single-GPU form
    ├─ Vulkan dual-row form
    ├─ Vulkan resident form
    ├─ Vulkan MLA form
    ├─ Sparse expert form
    └─ Streamed window form
    │
    ▼
PolyCompiler (receipt-driven) → KernelForm + KernelReceipt
    │
    ▼
ExecutionView (ephemeral address + lease)
    │
    ▼
Kernel executes → output
    │
    ▼
ReverseReceipt (proves execution)
```

### The key inversion
| Before | After |
|--------|-------|
| `wt.data` flows through every path | `BackingRef` resolves to bytes ONLY inside resolver |
| Kernel = fixed function + device | Kernel = semantic identity + generated form |
| GPU residency = implicit in dispatch | GPU residency = explicit in Heartbeat/Beacon |
| Hotpatch = binary mutation | Hotpatch = binding swap (verified) |
| Address = identity | Identity = persistent, Address = ephemeral |

---

## 8. Next Action: Implement Reverse Layer

```text
1. Create src/deep2/ReverseLayer.{h,cpp}
   - NanoAddress emission from KernelIntent + BackingRef
   - Heartbeat/Beacon query interface
   - BackingRef resolution from GGUF mmap / prepared cache / GPU residency

2. Create src/deep2/PolyKernelGenerator.{h,cpp}
   - PrimitiveGraph for MatrixVector (Q4_K, Q6_K, F32, F16, BF16)
   - Backend lowering for CPU (AVX2/AVX512) and Vulkan
   - Source emission + receipt-driven compilation

3. Wire one pilot: Q4_K GEMV in LinearW() EV path
   - Replace QuantKernelRegistry::GetGEMVEV(12) call
   - Route through ReverseLayer → PolyKernelGenerator
   - Verify Gate 1-3 PASS

4. Extend to grouped QKV and MoE expert paths
```

**This replaces the entire `QuantKernelRegistry` dispatch table with a semantic, polymorphic, receipt-certified generator.**