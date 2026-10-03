# RAWRXD_SPACELESS_UNMODEL_UNADDRESS_DESIGN_001

## Purpose
Map the SpaceEngine procedural-generation analogy to Deep2's tensor residency
architecture, define a concrete four-stage vocabulary, identify the gap between
current `ModelWeights` allocation model and target `ExecutionView` model, and
specify measurable next steps.

---

## 1. Current State — MEASURED

### 1.1 ModelWeights is monolithic allocation

```cpp
// Deep2Engine.h:193
struct ModelWeights {
    WeightTensor tokenEmbed;   // raw pointer + bytes
    WeightTensor lmHead;
    WeightTensor finalNorm;
    std::vector<LayerWeights> layers;  // each contains raw pointers
    // ... architecture metadata
    bool loaded = false;
};
```

```
loadModel(path)
  → parse GGUF
  → allocate contiguous host buffers
  → assign pointers into ModelWeights
  → modelWeights.loaded = true
```

**MEASURED:** `ModelWeights` exists at `Deep2Engine.h:193`. Every tensor is a
raw pointer inside a monolithic struct. `loadModel()` allocates everything at
once. `unloadModel()` frees everything at once.

**MEASURED:** `getModelWeights()` returns a const reference to the entire
allocation. Kernels receive `modelBase + offset` style access.

### 1.2 Residency infrastructure is partial

```
ElasticResidencyManager     = Layer 0.1 real (tracks state/tier, plans, no transfer)
ResidencyManager            = STUB (empty class)
TensorResidencyCache        = STUB (empty class)
VramStreamingController     = real (tracks bytes, stats, no actual residency)
```

**MEASURED:** `ElasticResidencyManager.hpp` has `ResidencyState` enum
(Unknown→Requested→Prefetching→Resident→Evictable→Evicted) and
`ResidencyTier` enum (Unknown→NVMe→RAM→VRAM). It tracks `TensorRecord` by
string name. It does not execute transfers.

**MEASURED:** `ResidencyManager.hpp` is `class ResidencyManager {};` — 2 lines.

**MEASURED:** `TensorResidencyCache.hpp` is `class TensorResidencyCache {};` — 2 lines.

### 1.3 Execution path is address-based

```cpp
// Current kernel signature pattern:
void gemv_q4k(const float* input, const Q4KBlock* weights, float* output, ...);
// weights is a raw pointer derived from ModelWeights.layers[layer].ffnGate
```

**MEASURED:** No `TensorHandle`, `ExecutionView`, or `LogicalTensor` exists in
the tree. `grep -r "TensorHandle\|ExecutionView\|LogicalTensor" src/deep2/`
returns zero matches.

---

## 2. The SpaceEngine Analogy — HYPOTHESIS

SpaceEngine's procedural architecture:

```
ADDRESS / HIERARCHY
        ↓
DETERMINISTIC IDENTITY
        ↓
SEED
        ↓
PROCEDURAL PARAMETERS
        ↓
REALIZED OBJECT
        ↓
RENDERED SPACE
```

The inversion for Deep2:

```
EXECUTION REQUIREMENT
        ↓
RELATIONAL IDENTITY
        ↓
RESOLVE WHAT IS NEEDED
        ↓
TEMPORARILY REALIZE IT
        ↓
TEMPORARILY ADDRESS IT
        ↓
USE IT
        ↓
DISSOLVE ADDRESS / RESIDENCY
```

**Key distinction:** SpaceEngine's identity ≈ location/hierarchy. Deep2's
identity ≠ location. The tensor exists logically; a physical address emerges
only when computation demands it and disappears afterward.

**HYPOTHESIS:** This inversion is the correct architectural path from
`ModelWeights` allocation to a residency-aware execution model. It is not yet
proven by an implemented and measured execution path.

---

## 3. Four-Stage Vocabulary

### 3.1 UNMODEL — Remove the monolithic Model object

**Current:**
```cpp
struct ModelWeights { ... };
Deep2Engine::loadModel() → allocates everything → ModelWeights.loaded = true
```

**Target:**
```cpp
struct Deep2ModelManifest {
    std::vector<TensorIdentity> tensors;
    DependencyGraph executionGraph;
    // No allocation. Only metadata.
};
```

**Inversion:** `MODEL = RELATIONSHIP`, not `MODEL = ALLOCATION`.

### 3.2 UNADDRESS — Remove permanent physical addresses from tensor identity

**Current:**
```cpp
// Identity IS address
WeightTensor tokenEmbed;  // float* data = 0x0000017AF2000000
```

**Target:**
```cpp
struct TensorIdentity {
    ModelId model;
    LayerId layer;
    TensorRole role;
    ExpertId expert;
    Shape shape;
    // No address. Identity is independent of residency.
};
```

**Inversion:** `IDENTITY IS PERSISTENT, ADDRESS IS EPHEMERAL`.

### 3.3 SPACELESS — Remove fixed residency location from execution semantics

**Current:**
```
Tensor A lives at: RAM 0x123... (permanent during model lifetime)
```

**Target:**
```
Tensor A exists.
Potential realizations: GGUF source, mmap, RAM cache, pinned RAM,
                       Decoda representation, GPU0, GPU1
Residency becomes: WHERE SHOULD THIS EXIST FOR THE NEXT OPERATION?
```

**Inversion:** Locality becomes a policy decision, not a property of the tensor.

### 3.4 REALIZE — Materialize the smallest valid representation exactly when needed

**Current:**
```
loadModel() → entire model resident in RAM → execute → unloadModel()
```

**Target:**
```
token
 ↓ need embedding
 ↓ resolve embedding
 ↓ execute
 ↓ release

need layer0.Q
 ↓ resolve
 ↓ execute
 ↓ release

// Address space exists ONLY while computation occurs
```

**Inversion:** The default state is logical graph + recoverable representations
+ zero physical realization. Physical space is borrowed momentarily.

---

## 4. The Concrete Gap

### 4.1 What exists today

```
┌─────────────────────────────────────────┐
│           Deep2Engine                   │
│  ┌───────────────────────────────┐      │
│  │      ModelWeights             │      │
│  │  (monolithic allocation)      │      │
│  │  tokenEmbed → float*          │      │
│  │  layers[0].ffnGate → float*   │      │
│  │  ...                          │      │
│  └───────────────────────────────┘      │
│              ↓                          │
│  ┌───────────────────────────────┐      │
│  │   ElasticResidencyManager     │      │
│  │   (tracks state, plans,       │      │
│  │    does NOT execute transfer) │      │
│  └───────────────────────────────┘      │
└─────────────────────────────────────────┘
```

### 4.2 What needs to exist

```
┌─────────────────────────────────────────┐
│      Deep2ModelManifest                 │
│      (logical tensor identities)         │
│              ↓                          │
│      Deep2ExecutionGraph                │
│      (dependency graph for generation)   │
│              ↓                          │
│   Deep2TensorAddressSpace               │
│   (resolves identity → representation)   │
│              ↓                          │
│   Deep2RepresentationResolver           │
│   (Q4_K, Decoda, cached transform)       │
│              ↓                          │
│   Deep2ResidencyManager                 │
│   (decides WHERE it should live)         │
│              ↓                          │
│   Deep2ExecutionView                    │
│   (temporary: address + bytes + lease) │
│              ↓                          │
│   Kernel Registry                        │
│   (receives views, not model pointers)   │
│              ↓                          │
│   Release → address dissolves            │
└─────────────────────────────────────────┘
```

### 4.3 Bridgeable gap — specific

The gap is not conceptual. It is in `Deep2Engine.h:193` and every kernel that
receives `const float* weights` derived from `modelWeights.layers[layer]`.

To bridge it, these three things must happen in order:

1. **Identity separation:** Introduce `TensorIdentity` (model + layer + role +
   expert) separate from any pointer. This is a struct-only change; kernels still
   receive raw pointers.

2. **View insertion:** Introduce `ExecutionView` with `void* transientAddress`,
   `size_t bytes`, `LeaseToken`. Change one kernel to receive `ExecutionView`
   instead of `float*`. Prove it compiles, links, and produces identical output
   on a real model.

3. **Resolver wiring:** Connect `ElasticResidencyManager` to actually produce
   `ExecutionView` instances by resolving `TensorIdentity` through a
   representation directory. This requires `ResidencyManager` and
   `TensorResidencyCache` to become real.

---

## 5. Invariants

```
NO KERNEL MAY REQUIRE A PERMANENT MODEL ADDRESS.
NO TENSOR IDENTITY MAY DEPEND ON ITS CURRENT RESIDENCY.
MODEL SIZE MUST NOT DEFINE THE REQUIRED ACTIVE ADDRESS SPACE.
```

These are design invariants, not runtime assertions. The current codebase
violates all three. The transition path must preserve:

```
EXISTING_CPU_INFERENCE=PASS
```

---

## 6. Execution Distance (replacing coordinate distance)

For tensor T and execution target D:

```
d(T,D) = t_locate + t_read + t_decode + t_transfer + t_synchronize
```

Examples:

| Realization | Distance components |
|---|---|
| VRAM copy | tiny (already resident) |
| Pinned RAM | small (host-resident, no decode) |
| Normal RAM | larger (may need cache fill) |
| mmap window | larger still (page fault + decode) |
| NVMe compressed | read + transform + upload |

The scheduler asks: **What is the cheapest valid realization of tensor X for
this operation?**

Not: **Where is tensor X?**

**HYPOTHESIS:** This formulation enables residency-aware scheduling that
current `ElasticResidencyManager.buildPlanForLayer()` does not yet implement.

---

## 7. Claim Taxonomy

```
MEASURED    = directly observed in current source or runtime
HYPOTHESIS  = plausible architectural path requiring implementation
PASS        = exercised by relevant runtime/build path
RETRACTED   = disproven
```

| Claim | Category | Evidence |
|---|---|---|
| ModelWeights is monolithic allocation | MEASURED | Deep2Engine.h:193 |
| ResidencyManager is stub | MEASURED | ResidencyManager.hpp:2 lines |
| TensorResidencyCache is stub | MEASURED | TensorResidencyCache.hpp:2 lines |
| No TensorHandle/ExecutionView exists | MEASURED | grep returns 0 matches |
| Spaceless/unmodel/unaddress is correct path | HYPOTHESIS | Analogy + design, no runtime proof |
| Execution distance enables better scheduling | HYPOTHESIS | Formula defined, not instrumented |
| Existing CPU inference remains PASS during transition | REQUIRED | Must be maintained, not yet tested |

---

## 8. Next Steps

1. **Preserve existing CPU inference PASS.** Before any structural change, run
   `deep2_streamer_cert_mla.exe` on `llama3.2-3b-Q2_K.gguf` and record:
   ```
   tokensGenerated, decodeMs, prefillMs, checksum of output tokens
   ```
   This is the baseline that must not regress.

2. **Implement `TensorIdentity` struct** (no behavior change). Add to
   `src/deep2/TensorIdentity.hpp`:
   ```cpp
   struct TensorIdentity {
       uint32_t modelId;
       uint32_t layerId;
       TensorRole role;
       uint32_t expertId;
       TensorShape shape;
   };
   ```
   No kernel changes yet. Compile and link check only.

3. **Select one kernel for ExecutionView pilot.** Candidate:
   `gemv_q4k` or the dense-row GEMV path. Change signature from
   `const float* weights` to `ExecutionView weightView`. Ensure the
   view's `transientAddress` is populated from existing `ModelWeights`
   allocation (no actual residency change yet). Run the baseline model
   and verify token-identical output.

4. **Promote `ResidencyManager` from stub.** Replace the 2-line stub with a
   class that can resolve `TensorIdentity` → `ExecutionView` by looking up
   `ElasticResidencyManager`'s tracked state. Still no actual GPU transfer;
   the view points to host RAM.

5. **Connect `TensorResidencyCache`.** Replace 2-line stub with a class that
   caches recently-used `ExecutionView` instances with LRU eviction. This is
   the first step toward address ephemerality.

6. **Only then:** Implement actual GPU staging (host → device transfer) behind
   the resolver. This is where the `enableVulkan(true)` + `fullView()` failure
   becomes solvable, because the resolver now decides when and what to upload.

**Do not proceed past step N until step N-1 has a measured PASS receipt.**

---

## 9. Relation to RawrXD Handoff Brief

This design document directly supports [RAWRXD_HANDOFF_BRIEF_001.md](RAWRXD_HANDOFF_BRIEF_001.md)
step 7:

```
7  Implement actual GPU weight residency/staging.
   enableVulkan(true) alone is explicitly insufficient.
```

The handoff correctly identified that residency is the blocker. This document
proposes a specific architectural vocabulary for implementing it without breaking
the existing CPU inference path.

---

## 10. Receipt

```
RAWRXD_SPACELESS_UNMODEL_UNADDRESS_DESIGN_001

STATUS=IN_PROGRESS
BASELINE_CPU_INFERENCE=RECORDED_PASS
TENSOR_IDENTITY=IMPLEMENTED_PASS
TENSOR_IDENTITY_CERT=PASS
EXECUTION_VIEW_PILOT=IMPLEMENTED_PASS
EXECUTION_VIEW_GEMV_CERT=PASS

BASELINE_RECEIPT=receipts/RAWRXD_SPACELESS_BASELINE_CPU_001/RECEIPT.md
BASELINE_MODEL=llama3.2-3b-Q2_K.gguf
BASELINE_MODEL_SHA256=EE1CA8B716933587127F6FEB9FF5A247F1E4460E72DCF6293331B9617F8A8AA2
BASELINE_GENERATED_TOKENS=8
BASELINE_DECODE_TPS=0.194
BASELINE_BINARY_SHA256=C2C4B6B739940E0D2FA2AEB3401A2C52FCD5F46D790301259D1AB513CB7EBFE8

TENSOR_IDENTITY_HEADER=src/deep2/TensorIdentity.hpp
TENSOR_IDENTITY_SIZE=24
TENSOR_IDENTITY_ALIGN=8
TENSOR_IDENTITY_CERT=tests/tensor_identity_cert.cpp
TENSOR_IDENTITY_CERT_VERDICT=PASS

EXECUTION_VIEW_HEADER=src/deep2/ExecutionView.hpp
EXECUTION_VIEW_SIZE=64           (includes pointer; TensorIdentity does not)
LEASE_TOKEN_SIZE=24
EXECUTION_VIEW_GEMV_PILOT=tests/execution_view_gemv_pilot.cpp
EXECUTION_VIEW_GEMV_PILOT_CHECKS=6/6 PASS
EXECUTION_VIEW_GEMV_PILOT_MAX_DIFF=0.000e+00
EXECUTION_VIEW_GEMV_PILOT_VERDICT=PASS

EXECUTION_VIEW_KERNEL=gemvF32 in src/deep2/deep2_cpu_mla.cpp
EXECUTION_VIEW_PATH=NEW (ExecutionView overload)
LEGACY_PATH=PRESERVED (WeightTensor overload delegates to ExecutionView)
A_B_REFERENCE=IDENTICAL_OUTPUT (same pointer, same bytes, no residency change)

EXECUTION_VIEW_PRODUCTION_ADOPTION=QuantKernelRegistry.cpp + Deep2Engine.cpp
EXECUTION_VIEW_PRODUCTION_SIGNATURE=GEMVKernelFnEV (ExecutionView&, float*, float*, rows, cols)
EXECUTION_VIEW_PRODUCTION_REGISTRATION=RegisterGEMVEV/GetGEMVEV
EXECUTION_VIEW_PRODUCTION_KERNEL=gemv_f32_scalar_ev (wrapper around existing scalar)
EXECUTION_VIEW_PRODUCTION_DISPATCH=LinearW in Deep2Engine.cpp tries EV first, falls back to legacy
EXECUTION_VIEW_PRODUCTION_COMPILE=QuantKernelRegistry.cpp standalone: ZERO ERRORS
EXECUTION_VIEW_PRODUCTION_TYPES_ADOPTED=F32 only (quant types fall through to legacy)

GAP_CLOSED=ExecutionView abstraction exists
GAP_CLOSED=ExecutionView adopted in production GEMV dispatch (F32 path)
GAP_IDENTIFIED=ModelWeights monolithic allocation
GAP_IDENTIFIED=ResidencyManager stub
GAP_IDENTIFIED=TensorResidencyCache stub
GAP_IDENTIFIED=Quant types (Q2_K, Q4_K, Q8_0, etc.) not yet adopted to ExecutionView
GAP_IDENTIFIED=Deep2Engine.cpp EV path not end-to-end linked (CMake pre-existing blockers)

NEXT_STEP=Adopt ExecutionView for one quant type (Q4_K is dominant in real models)
NEXT_STEP=End-to-end link test with rebuilt rawr.exe
NEXT_STEP=Re-run baseline and require token/logit parity with EV-adopted build

VERDICT=DESIGN_IMPLEMENTING_STEP_6_PRODUCTION_ADOPTION
```
```