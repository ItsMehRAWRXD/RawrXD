# RAWRXD_MODEL_SUPPORT_SPEC_001

Local model support for Deep2. Admission-time architecture resolution, real
recurrent math, real kernels, and Windows-appropriate certification.

Status: `AUTHORED_UNVERIFIED` — this document has not been executed against a
build. Nothing here is a PASS claim.

---

## 0. Scope correction

Two different things are being conflated. They must be separated before any
implementation.

### 0.1 What Deep2 actually does

Deep2 is a local inference runtime. It executes **GGUF files on the local
machine**. Its unit of support is a *GGUF architecture family* — the value of
`general.architecture` in a GGUF header. There are 25 known values and the
catalog is closed (src/deep2/Deep2ModelArchitecture.hpp:16).

### 0.2 What a 554-name provider catalog is

A list like `anthropic/claude-opus-5.5` or `nvidia/nemotron-3-ultra-550b-a55b`
is a **hosted endpoint identifier**. Those weights are not distributable. Deep2
cannot execute them locally and will never produce a token from them.

RawrXD may legitimately *carry* that catalog, for two purposes:

1. `rawr dump` lists it, so the user sees what their Kilo/Agent Manager
   session can reach.
2. `ModelCatalogAuthority` (src/models/ModelCatalogAuthority.cpp) resolves a
   local GGUF filename back to a catalog entry so the two views reconcile.

What RawrXD may **never** do is report a hosted model as locally supported,
count it toward a local-inference gate, or let it enter `admitModel`.

**The hosted proxy is out of scope for this spec.** An OpenAI-compatible
upstream forwarder belongs to `RAWRXD_HOSTED_PROXY_SPEC_002`, not here.
Evidence from `src/deep2/deep2_openai_server.cpp`: `grep provider|backend|
upstream|remote` returns **zero** matches, so the file has no outbound HTTP
client and no provider abstraction. `/v1/models` (line 458-475) hardcodes
`{"owned_by", "deep2-local"}` and emits exactly one entry. Building hosted
proxying means an outbound credential store, API-key secret handling, a second
trust boundary, and provider-specific request translation — none of which
exist today, and none of which are architecture-catalog concerns. Folding that
into a spec whose Batch 1 is "implement the architecture registry" would put a
whole auth/transport subsystem behind a Deep2 registry gate, and the first
thing that breaks would be the gate's meaning.

### 0.3 Non-goals

- No hash-only model identity. See §3.4.
- No architecture selection inside `forwardLayer`. See §3.2.
- No quantization tags in architecture identity. See §3.3.
- No compiled registries of hosted endpoint names in assembly or `.rdata`.
  The catalog is data read from config, discoverable by `rawr dump`.
- No hosted-endpoint proxy, credential store, or outbound HTTP transport.
  That is `RAWRXD_HOSTED_PROXY_SPEC_002`. See §0.2.
- No MBA or other semantics-preserving obfuscation as a security control.
  It is trivially invertible by symbolic execution and creates false assurance.

---

## 1. Verified current state

Everything in this section was read from the worktree at HEAD `94cd2fadf`,
branch `model-correctness`.

### 1.1 Real and wired

| Component | Location | Notes |
|---|---|---|
| Architecture traits catalog | `src/deep2/Deep2ModelArchitecture.hpp` | 25 `Kind` values, `resolve()` returns `Traits`, `familyName()`, `isKnown()`. Header-only, included by `Deep2ArchitectureRuntime.hpp`. |
| Recurrent math reference | `src/deep2/Deep2RecurrentMath.hpp` | `silu`, `softplus`, `l2Normalize`, `depthwiseConvStep`, `gatedDeltaNetStep`, `mamba2Step`, `rmsNormGated`, `finite`. |
| Mamba2 in production | `src/deep2/Deep2Engine.cpp:3782` `computeSSM()` | 250 lines. Real projection, depthwise conv, selective scan, skip-D, gated norm, out-proj. Fails closed by `throw`. |
| Nemotron-H per-layer pattern | `src/deep2/Deep2Engine.cpp:967-1000` | Reads `attention.head_count_kv` / `feed_forward_length` as per-layer arrays. Fails closed on wrong length. |
| SSM allocation guards | `src/deep2/Deep2Engine.cpp:664-678, 756-767` | `ssmHeads_ > 0 && ssmStateSize_ > 0` guards present after the D2 divide-by-zero fix. |
| GGUF loader | `src/deep2/GGUFLoader.hpp` (34 KB) | Metadata, tensor lookup, mmap, sharding. |
| Tokenizer | `src/deep2/Tokenizer.cpp` (28 KB) | No-dependency GGUF tokenizer. |
| Chat template | `src/deep2/ChatTemplate.cpp` (30 KB) | Model-aware. |
| Sampler | `src/deep2/Sampler.cpp` (10 KB) | Real. |
| OpenAI-compatible server | `src/deep2/deep2_openai_server.cpp` (35 KB) | `/v1/models`, `/v1/chat/completions`, SSE streaming, chunked transfer. |
| GPU scheduler | `src/deep2/GpuScheduler.cpp` (11.8 KB) | Dual-GPU policy, fail-closed. |
| NVMe streaming | `src/deep2/NVMeStream.cpp` (10.6 KB) | Real async file-backed streaming. |
| Model catalog | `src/models/ModelCatalogAuthority.cpp` (18.6 KB) | Real filesystem scan, real GGUF metadata probe. |
| `rawr dump` | `src/cli/RawrDumpAuthority.cpp` (24.6 KB) | Reimplemented against the real filesystem after retraction. |

### 1.2 Authored but dead

| Component | Location | Why dead |
|---|---|---|
| `ArchitectureRuntime` class | `src/deep2/Deep2ArchitectureRuntime.hpp:50` | Header is `#include`d at `Deep2Engine.cpp:12` but the class is **never constructed**. Only `Arch::Ref::*` free functions are called (`Deep2Engine.cpp:3783-3787`). The GDN and Mamba2 `forward` paths inside it are unreachable. |
| `ModelRegistry` class | `src/deep2/Deep2ModelRegistry.hpp:205` | Full declaration: `Architecture` descriptor, `ProbeFn`/`LoadFn`/`CreateContextFn`/`ForwardFn`/`ResetGenerationFn`/`DestroyFn`, FNV-1a `hash_const`/`hash_runtime`, `canonicalize()`, `ModelMetadata`, `LoadResult`, `ForwardRequest`, `ArchitectureForwardResult`. No `.cpp`. `src/deep2/ModelRegistry.cpp` is a 38-byte stub. The header is `#include`d nowhere. |
| Name collision — `ForwardResult` | `Deep2Engine.h:608` vs `Deep2ModelRegistry.hpp:186` | Resolved. The registry type was renamed to `ArchitectureForwardResult`. The engine's `ForwardResult` is live: it is the return type of `forwardTokenAllLayers()` (`Deep2Engine.h:614`) and reports `ExecutionRoute` + `gpuCommitted`, so it must not be renamed. |
| Dead two-field tag | `Deep2Engine.h:425` `ModelMetadata` | Resolved by deletion. `getModelMetadata()` had no definition in any translation unit and no call site anywhere in the tree; `grep Metadata` over `Deep2Engine.cpp` (5396 lines) returns zero matches, and there is no backing member. The lines were removed. The live metadata type is `Deep2::ModelMetadata` in the registry header. |

### 1.3 Stubs that look like features

- All 21 `src/deep2/sovereign_*.asm` files are `; Auto-generated stub` →
  `xor eax,eax; ret`. Includes `sovereign_q4k_gemv.asm`,
  `sovereign_moe_fused.asm`, `sovereign_q6_k_gemv.asm`.
- `src/deep2/VwaRangeX64.asm`, `src/deep2/asm_stubs.cpp`,
  `src/deep2/CPUFrequency.cpp`, `src/deep2/BottleTTL.cpp`,
  `src/deep2/BP16Extractor.cpp` — stubs.
- ~90 `src/deep2/deep2_*_cert.cpp` files are 40-70 byte `// STUB:` comments
  (e.g. `deep2_k2_mla_fused_q4kt_cert.cpp`). Several are listed in
  `CMakeLists.txt:7918+` and therefore compile as empty translation units.
- `src/deep2/ModelLoader.cpp`, `GGUFLoader_Fixed.cpp`, `GGUFVerifier.cpp`,
  `FabricTensorTable.cpp`, `PatchCache.cpp`, `HotPatcher.cpp` — stubs.
- `src/deep2/Deep2ModelRuntime.cpp` has a real class shell but
  `LoadModel` sets `model_loaded_ = true` without loading anything and
  `Generate` appends the literal string `" tok"`. It must not be linked into
  any product target until real.

### 1.4 Architecture-specific dispatch in the engine root

7 string comparisons on `modelArchitecture_` (Deep2Engine.cpp):

| Line | Comparison | Legitimate? |
|---|---|---|
| 2241, 3100, 3142, 3411 | `== "gemma3"` | Yes — Gemma3 alternates 5:1 local/global attention and has distinct norms. Legitimately architecture-owned. |
| 665, 2927 | `== "nemotron_h" \|\| == "nemotron_h_moe"` | Yes — SSM buffer geometry. |
| 3490 | `!= "nemotron_h_moe"` | Yes — MoE expert count differs. |

This is the correct *shape* (few, allocation/geometry-motivated) but it lives in
the engine root. §3.2 moves it behind descriptors.

---

## 2. Target architecture

```
   admitModel(path)                    <-- the ONLY architecture resolution point
        |
        v
   +--- Probe ------------------------------------------+
   |   GGUFLoader -> general.architecture               |
   |   Arch::resolve(arch) -> Traits                    |
   |   REJECT if Kind::Unknown                          |
   |   REJECT if Traits::requiresSpecialGraph           |
   |        (deepseek4, gpt-oss, laguna)                 |
   +-----------------------------------------------------+
        |
        v
   +--- Load --------------------------------------------+
   |   geometry resolution, tensor bind, per-layer      |
   |   pattern arrays, allocation                       |
   +-----------------------------------------------------+
        |
        v
   Architecture&  ---- held by Deep2Engine as one object, immutable after load
        |
        +---> forwardLayer(i)  never sees an arch string
        +---> resetGeneration()
        +---> destroy()
```

---

## 3. Invariants

These are the acceptance criteria for Batch 1. Each maps to a measured receipt
field. No field may be a literal.

### 3.1 `ARCH_SELECTION_DURING_FORWARD = 0`

`forwardLayer` and everything it calls must not compare an architecture string.
Measured by: a `rg 'modelArchitecture_ ==' src/deep2/Deep2Engine.cpp` count,
reported in the receipt as `ARCH_IF_CHAINS_OUTSIDE_DESCRIPTORS`. Target `0`.

### 3.2 Architecture owns its layer topology

A descriptor may answer per-layer questions. Nemotron-H's M/E/*/- pattern and
Qwen3-Next's attention/GDN interleave are architecture facts, not engine facts.
`Architecture` gains a `layerMixer(layerIndex) -> Mixer` entry point so
`forwardLayer` asks the descriptor instead of branching.

### 3.3 Quantization is not architecture identity

`Q4_K_M`, `Q8_0`, `IQ2_M`, `BF16`, `NVFP4` are storage and kernel concerns.
`canonicalize("qwen3-8b-q4_k_m") == "qwen3"`. A quantization suffix must never
select a different forward implementation.

### 3.4 Alias resolution is hash **and** string

```
resolve(name):
    h = hash_runtime(name)
    for alias in registry:
        if alias.hash == h AND alias.name == name:   # both, always
            return alias.architecture
    return nullptr                                    # fail closed
```

FNV-1a alone is forbidden. Two names in the catalog may collide; string
equality disambiguates. Measured field: `ALIAS_HASH_ONLY_MATCHES_BLOCKED`.

### 3.5 Unknown architecture fails closed

`Kind::Unknown` → `loadModel` returns `false` with
`diag->stageName = "ARCH_UNKNOWN"`. It must not fall through to Llama math.

### 3.6 Special graph means special graph

`deepseek4`, `gpt-oss`, `laguna` carry `requiresSpecialGraph = true`. They are
recognized so they can be *named* in diagnostics, and they are refused at
admission. They must never be counted in any forward-execution gate.

### 3.7 One architecture per load

`Deep2Engine` holds `const Architecture* active_`. `switchModel` tears the old
one down before admitting the new. No second registry lookup happens after
`admitModel` returns.

---

## 4. Batch 1 — Registry and admission

**Branch discipline:** linkage/CMake composition goes to
`audit-session-2-cleanup`. Numerical certification goes to `model-correctness`.
Per the stored constraint, a linkage fix enters model-correctness only if it is
strictly required to execute a parity gate.

### 4.1 Name collisions — RESOLVED

Both collisions named in §1.2 are closed. This section is retained as
provenance so Batch 1 does not re-open them.

**`ModelMetadata` — resolved by deletion.** The engine's
`struct ModelMetadata { std::string name; uint32_t version = 0; }` and
`const ModelMetadata& getModelMetadata() const` were removed from
`Deep2Engine.h`. Evidence gathered before removal:

- `getModelMetadata()` had **no definition** in any translation unit.
- It had **no call site** anywhere in the repository; the only hits were the
  declaration line and three `.bak` snapshots.
- `Deep2Engine.cpp` contains **zero** occurrences of `Metadata`.
- No backing member (`modelMetadata_`) existed, so the struct could not be
  observed even in principle.

Nothing could link against it, so removal is source-only and zero-risk. The
registry's rich `ModelMetadata` is now the single metadata type, which is also
the one the GGUF loader populates.

**`ForwardResult` — resolved by renaming the registry side.** The spec's earlier
suggestion to rename it `ArchitectureStepResult` was not followed; the chosen
name is `ArchitectureForwardResult` because the type is the result of an
architecture forward *call*, and the descriptor's `forward` slot is where it is
returned. Do not rename the engine's `ForwardResult`: it is live, returned by
`forwardTokenAllLayers()`, and reports `ExecutionRoute` and `gpuCommitted`.
The two are genuinely different types with different jobs, and the rename
documents that rather than hiding it.

Compile evidence: `Deep2Engine.cpp` compiles clean (`EXITCODE=0`) with the real
`InferenceEngine` flag set from `build_embed_parity/compile_commands.json`, and
a probe TU that includes `Deep2ModelRegistry.hpp` and `static_assert`s all three
of `ModelMetadata`, `ArchitectureForwardResult`, and
`Deep2Engine::ForwardResult` compiles clean (`EXITCODE=0`). That probe is the
regression guard: it fails to build if either name is reintroduced ambiguously.

The registry header also gained explicit `#include <string>`, `<string_view>`,
`<vector>`, `<cstddef>`, `<cstdint>`. It previously relied on `Deep2Engine.h`
transitively for `<string>` and `<vector>` while declaring `std::string` and
`std::vector` members of its own.

### 4.2 Implement `ModelRegistry.cpp`

```cpp
// src/deep2/ModelRegistry.cpp
#include "Deep2ModelRegistry.hpp"
#include <array>
#include <mutex>

namespace Deep2 {
namespace {

// Descriptors, one per supported family. Populated in Batch 2/3.
extern const Architecture kGenericTransformer;
extern const Architecture kGenericMoe;
extern const Architecture kMla;
extern const Architecture kGatedDeltaNet;
extern const Architecture kMamba2;
// Special graphs intentionally absent — they are refused, not implemented.

constexpr std::array<ModelAlias, 5> kAliases{{
    { hash_const("llama"),   "llama",   &kGenericTransformer },
    { hash_const("qwen2"),   "qwen2",   &kGenericTransformer },
    { hash_const("qwen3"),   "qwen3",   &kGenericTransformer },
    { hash_const("deepseek2"), "deepseek2", &kMla },
    { hash_const("nemotron_h"), "nemotron_h", &kMamba2 },
}};

std::mutex g_mu;

} // namespace

const Architecture* ModelRegistry::resolve(std::string_view modelName) noexcept {
    const uint64_t h = hash_runtime(modelName.data());
    for (const auto& a : kAliases) {
        // Both conditions. Hash alone would admit a collision.
        if (a.hash == h && a.name == modelName) return a.architecture;
    }
    return nullptr;
}

const Architecture* ModelRegistry::resolve(const ModelMetadata& m) noexcept {
    if (m.canonicalName.empty()) return nullptr;
    return resolve(m.canonicalName);
}

void ModelRegistry::registerArchitecture(const Architecture*) {
    // Frozen at link time. Registration after first resolve is a defect;
    // fail closed rather than mutate a table that admitModel may be reading.
    std::lock_guard<std::mutex> lk(g_mu);
    std::terminate();
}

void ModelRegistry::listArchitectures(std::vector<std::string_view>& out) {
    for (const auto& a : kAliases) out.push_back(a.architecture->id);
}

void ModelRegistry::listAliases(std::vector<std::string_view>& out) {
    for (const auto& a : kAliases) out.push_back(a.name);
}

bool ModelRegistry::knows(std::string_view name) noexcept {
    return resolve(name) != nullptr;
}

} // namespace Deep2
```

`canonicalize()` strips a quantization suffix and a file extension, lowercases,
and returns the architecture token. It must not invent an architecture: if the
remaining token is not in the table, return `""`.

### 4.3 Extend the descriptor

```cpp
enum class Mixer : uint8_t { Attention, GatedDeltaNet, Mamba2, Mlp, MoE };

struct Architecture {
    std::string_view id;
    ProbeFn          probe;
    LoadFn           load;
    CreateContextFn  createContext;
    ForwardFn        forward;
    ResetGenerationFn resetGeneration;
    DestroyFn        destroy;

    // Added for Batch 1 so forwardLayer stops branching (invariant 3.2).
    Mixer       (*layerMixer)(std::size_t layerIndex) noexcept = nullptr;
    const char* (*canonicalArch)() noexcept = nullptr;
};
```

`layerMixer` may be null; the engine then requires `Traits::family` to be
uniform and uses the family default.

### 4.4 `admitModel`

```cpp
AdmissionResult Deep2Engine::admitModel(const std::string& path, ModelLoadDiag* diag) {
    GGUFLoader loader;
    if (!loader.load(path)) return {false, diag, "GGUF_LOAD_FAILED"};

    const std::string arch = loader.getMetaString("general.architecture");
    const Traits t = Arch::resolve(arch);

    if (t.kind == Arch::Kind::Unknown)   return {false, diag, "ARCH_UNKNOWN"};
    if (t.requiresSpecialGraph)          return {false, diag, "ARCH_SPECIAL_GRAPH"};

    const Architecture* a = ModelRegistry::resolve(arch);
    if (!a)                             return {false, diag, "ARCH_NOT_REGISTERED"};

    // Descriptor takes over from here. The engine stops reading arch strings.
    active_ = a;
    return a->load(*this, loader, t, diag);
}
```

### 4.5 Batch 1 receipt fields

All measured, none literal.

```
ARCH_REGISTRY_001=BATCH1
ARCH_SELECTIONS_DURING_FORWARD=0
ARCH_IF_CHAINS_OUTSIDE_DESCRIPTORS=0
ALIASES_REGISTERED=<count>
ALIASES_RESOLVABLE=<count>
ALIAS_HASH_ONLY_MATCHES_BLOCKED=<count of hash collisions proven rejected>
ARCH_UNKNOWN_REFUSED=<count>
ARCH_SPECIAL_GRAPH_REFUSED=<count>
ADMIT_FAIL_CLOSED=<1|0>
VERDICT=PASS|FAIL
```

The `ALIASES_RESOLVABLE` test iterates the table and asserts
`resolve(a.name) == &*a` for every entry. The
`ALIAS_HASH_ONLY_MATCHES_BLOCKED` test constructs a synthetic colliding name
and asserts it is refused.

---

## 5. Batch 2 — Make the recurrent paths real

`ArchitectureRuntime` exists and is correct in shape. It is simply never
constructed. That is the whole defect.

### 5.1 Decide: adopt or fold

**Recommendation: fold.** `Deep2ArchitectureRuntime.hpp` duplicates state that
`Deep2Engine` already owns (`ssmState`, `ssmConvState`, `ssmX`, `ssmY`,
`ssmTemp`, `ssmLayerCaches_`), and `computeSSM()` at
`Deep2Engine.cpp:3782` is already a working Mamba2. Two implementations of the
same math in one binary is how A008/A009 happened.

So: extract the GDN path from `ArchitectureRuntime::forwardGdn` into a real
`computeGatedDeltaNet()` alongside `computeSSM()`, and delete
`ArchitectureRuntime` once the GDN path is proven. Keep `Deep2RecurrentMath.hpp`
— it is shared, correct, and has no state.

### 5.2 `computeGatedDeltaNet()`

The reference implementation at
`Deep2ArchitectureRuntime.hpp:229-311` is a legitimate autoregressive GDN step.
Port it to `Deep2Engine.cpp` with engine-native buffers, and keep its two
subtleties:

- **Gating.** `g = softplus(alpha + dt_bias) * A` (line 291). GDN consumes
  `exp(g)`. Getting this wrong produces finite garbage, not a crash.
- **Qwen3-Next beta/alpha layout.** `ssm_beta_alpha.weight` interleaves as
  `[beta_0..beta_r, alpha_0..alpha_r]` per group (lines 271-273). Qwen3.5 uses
  separate `ssm_beta` / `ssm_alpha` / `attn_gate` tensors. Both branches are
  required and they are not interchangeable.

### 5.3 Hybrid dispatch

`layerMixer` resolves per-layer. Nemotron-H pattern comes from
`nemotronHeadKvPerLayer_` / `nemotronFfPerLayer_`, already parsed and validated
at `Deep2Engine.cpp:967`. Qwen3-Next's interleave is regular and belongs in the
Qwen3-Next descriptor.

### 5.4 Batch 2 receipt

```
ARCH_REGISTRY_001=BATCH2
GDN_FORWARD_IMPLEMENTED=<1|0>
MAMBA2_FORWARD_IMPLEMENTED=1
ARCH_RUNTIME_DUPLICATE_DELETED=<1|0>
GDN_NONFINITE_OUTPUTS=0
GDN_INPUT_OUTPUT_ALIAS_VIOLATIONS=0
HYBRID_LAYER_DISPATCH_FROM_DESCRIPTOR=1
ARCH_SELECTION_DURING_FORWARD=0
VERDICT=PASS|FAIL
```

---

## 6. Batch 3 — Kernels

Every `sovereign_*.asm` is a stub that returns 0. This is the largest
remaining gap and it is a throughput gap, not a correctness gap — the C++
kernels in `QuantKernelRegistry.cpp` (87 KB) do the real work today.

### 6.1 Priority order

Descending tok/s impact per unit of effort:

1. `sovereign_q4k_gemv.asm` — Q4_K is the dominant local quant.
2. `sovereign_q6k_gemv.asm` — the quality tier users actually pick.
3. `sovereign_moe_fused.asm` — MoE routing + expert GEMV fused.
4. `sovereign_fp16_gemv.asm`, `sovereign_fp8_gemv.asm` — secondary.

### 6.2 MASM rules

- Windows x64 ABI. `rcx/rdx/r8/r9` args, `xmm0-3` FP, 32-byte shadow space,
  callee-saved `rbx rbp rsi rdi r12-r15`.
- No calls out. No CRT. No `memset` — inline the stores.
- `vzeroupper` before every `ret`.
- Declare `.code`/`.end` explicitly. Do not rely on `END` alone; the current
  stubs are evidence that the file was never assembled.
- Every kernel gets a `; ABI:` comment block: in-ptr, in-rows, in-cols, in-type,
  out-ptr, out-rows, clobbers. `Deep2ArchitectureRuntime.hpp:24` already models
  this as `LinearFn`.

### 6.3 Build integration

MASM must be added to a target with `ASM_MASM` enabled. Currently the stubs
compile to nothing useful and `RAWRXD_PRODUCTION_STRIP_STUB_SOURCES=ON`
(`build_ide_cert/CMakeCache.txt`) does not detect them because they are `.asm`,
not listed sources.

Add to the Deep2 target:

```cmake
enable_language(ASM_MASM)
target_sources(deep2_kernels PRIVATE
  src/deep2/sovereign_q4k_gemv.asm
  src/deep2/sovereign_q6k_gemv.asm
  src/deep2/sovereign_moe_fused.asm
  src/deep2/sovereign_fp16_gemv.asm
)
```

### 6.4 Per-kernel parity gate

Each kernel is gated against the C++ reference in
`QuantKernelRegistry.cpp`, not against itself.

```cpp
// tools/deep2_asm_kernel_parity.cpp
// For each quant type Q in {Q4_K, Q6_K, Q8_0, FP16}:
//   generate N random input vectors (seeded, deterministic)
//   y_ref = QuantKernelRegistry::Instance().GetGemmv(Q)(x, w, n)
//   y_asm = sovereign_##Q##_gemv(x, w, n)
//   record max_abs_diff, max_rel_diff
// PASS requires max_rel_diff <= 1e-4 for Q4_K/Q6_K/Q8_0, 1e-6 for FP16
```

Receipt:

```
MASM_KERNELS_IMPLEMENTED=4
MASM_PARITY_Q4_K=<max_rel>
MASM_PARITY_Q6_K=<max_rel>
MASM_PARITY_Q8_0=<max_rel>
MASM_PARITY_FP16=<max_rel>
MASM_STUB_COUNT_REMAINING=0
VERDICT=PASS|FAIL
```

---

## 7. Batch 4 — Certification on Windows

The prior proposal in this repo's history specified an ASan / Valgrind /
libFuzzer / Kubernetes-Chaos-Mesh / Prometheus suite. None of it is applicable.
`clang` and `clang-cl` are both absent from this machine; Valgrind is
Linux-only; there is no cluster.

What follows uses only what is present: MSVC 14.44, Ninja, CMake, Vulkan SDK
1.4.357.0.

### 7.1 Build

```powershell
Set-Location F:\~dev\rawrxd
cmake --preset win32ide-strict
cmake --build --preset win32ide-strict
```

Generator Ninja, `CMAKE_BUILD_TYPE=Release`, target `RawrXD-Win32IDE`, binary dir
`F:/~dev/build_win32ide_strict`.

For the Deep2-only lifecycle gate there is an existing target
(`CMakeLists.txt:16565`):

```powershell
cmake -S F:\~dev\rawrxd\rawrxd -B F:\~dev\rawrxd\build_d2_001 `
  -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build F:\~dev\rawrxd\build_d2_001 --target deep2_generation_lifecycle_test
```

Note from stored project fact: `tools/deep2_generation_lifecycle_test.cpp` was
previously not in any target and had to be compiled by hand. It is now
registered at `CMakeLists.txt:16565` — verify rather than assume.

### 7.2 GATE-A: architecture admission

Proves §3.1-§3.7.

| Metric | Threshold |
|---|---|
| `ARCH_SELECTIONS_DURING_FORWARD` | `= 0` |
| `ARCH_IF_CHAINS_OUTSIDE_DESCRIPTORS` | `= 0` |
| `ADMIT_FAIL_CLOSED` | `= 1` |
| unknown-arch load attempts refused | `100%` |
| special-graph load attempts refused | `100%` of {deepseek4, gpt-oss, laguna} |
| hash-collision alias attempts accepted | `0` |

### 7.3 GATE-B: generation lifecycle

Extends the closed Batch 2 protocol. Four generations on one engine plus a
ceiling-terminated generation.

| Metric | Threshold |
|---|---|
| `FORWARD_FAILURE_REPORTED_AS_COMPLETED` | `= 0` |
| `CANCELLED_REPORTED_AS_COMPLETED` | `= 0` |
| `COMPLETED_WITH_ZERO_GENERATED_TOKENS` | `= 0` |
| `GENERATION_INHERITED_KV_FROM_PRIOR_GENERATIONS` | `= 0` |
| `SAME_ENGINE_ALL_GENERATIONS_PASS` | `= 1` |
| `D_TERMINATED_AT_CEILING` | `= 1` |

Also required, newly: no `specKvMirrorReset()` crash. The `D2` fix gated that
call behind `RAWRXD_ENABLE_SPEC_KV_RESET` (default off) because the
`InferenceEngine_patched.lib` implementation faults after the first generation.
The gate must assert the process survives to its last line.

### 7.4 GATE-C: recurrent math finiteness and determinism

| Metric | Threshold |
|---|---|
| `GDN_NONFINITE_OUTPUTS` | `= 0` |
| `MAMBA2_NONFINITE_OUTPUTS` | `= 0` |
| `GDN_RUNS_IDENTICAL_HASH` | `N=16` runs, one hash |
| `RESET_ZEROES_SSM_STATE` | `1` |
| `LONG_PROMPT_STATE_MATCHES_SERIAL` | `2048`-token prompt, chunked vs whole |

The long-prompt check is the one that catches the D2-class defect. Resetting
recurrent state and getting finite output is not the same as getting the *same*
state as a serial reference.

### 7.5 GATE-D: kernel parity

§6.4. Per-quant relative error against the C++ reference.

### 7.6 GATE-E: GPU numeric parity

Vulkan SDK 1.4.357.0 is present, so `compute-sanitizer` is available. This is
the MSVC-appropriate replacement for the proposed ASan pass.

```powershell
& "$env:VULKAN_SDK\Bin\compute-sanitizer.exe" `
  --tool memcheck `
  .\build_win32ide_strict\deep2_k2_gpu_numeric_parity_cert.exe `
  --model $ggufPath
```

| Metric | Threshold |
|---|---|
| `GPU_MEMCHECK_ERRORS` | `= 0` |
| `GPU_VS_CPU_MAX_REL_LOGIT_DIFF` | `<= 1e-3` (Q8_0 reference) |
| `GPU_NONFINITE_OUTPUTS` | `= 0` |

### 7.7 GATE-F: memory

Replaces the proposed `ΔM = 0` formula, which is not achievable for a runtime
that mmaps model weights and uses Vulkan device allocations.

| Metric | Threshold |
|---|---|
| `HOST_LEAK_BYTES` at process exit | `= 0` after explicit teardown |
| `PEAK_PRIVATE_BYTES` at 4 generations | `<= 1.10x` generation-1 peak |
| `VK_DEVICE_MEMORY_LEAK` | `= 0` |

Peak-growth ratio is the honest formulation. A flat `ΔM = 0` gate would fail on
the first allocation-growth step and teach the team to ignore it.

### 7.8 Honest performance framing

The prior proposal set `P99 TTFT <= 12.5 ms` and `>= 4500 tok/s per GPU node`.
Those are serving-frontend numbers and are unreachable for any model of the size
RawrXD targets. Do not adopt them.

Use the *roofline-relative* formulation already present in
`src/deep2/Deep2B60ModelContract.cpp`:

```
P10_ROOFLINE_FRACTION  >= 0.75
MEDIAN_ROOFLINE_FRACTION >= 0.80
P90_HOST_SYNC <= 0.03
P90_QUEUE_IDLE <= 0.04
MEDIAN_OVERLAP >= 0.85
RELOAD_BYTES = 0
HOST_MATERIALIZATIONS = 0
PEER_COPY_BYTES = 0
```

These are per-model contracts. `B61QwenNext`, `B62Nemotron`, `B63GptOss`,
`B64Laguna`, `B65DeepSeekFlash` already declare them. Each declares a different
`minP10RawTps` because the models differ by 25x in size; that is correct and
should not be collapsed into one global number.

### 7.9 Compilation is not a gate

A `.cpp` containing only `// STUB:` compiles successfully. It is in the build,
it produces a `.obj`, and it means nothing.

Add a structural check to the ledger run:

```powershell
$stubs = Get-ChildItem -Recurse -Include *.cpp,*.hpp,*.asm `
    -Path F:\~dev\rawrxd\src `
  | Where-Object { (Get-Content $_.FullName -TotalCount 4) -match 'Auto-generated stub|^\s*//\s*STUB:' }
"STUB_SOURCE_COUNT=$($stubs.Count)"
```

Gate: the count must decrease monotonically and the *listed-in-CMake* subset
must reach 0. Report both numbers. Reporting only the total hides the fact that
~90 listed certs compile to nothing.

---

## 9. Execution order

```
Batch 1  Registry + admission
   |     - resolve name collisions
   |     - implement ModelRegistry.cpp
   |     - extend Architecture with layerMixer
   |     - admitModel(), fail closed
   |     GATE: 4.5 receipt fields, GATE-A
   |
Batch 2  Recurrent math made reachable
   |     - fold ArchitectureRuntime into computeGatedDeltaNet
   |     - hybrid dispatch from descriptor
   |     - delete the duplicate
   |     GATE: 5.4 receipt fields, GATE-C
   |
Batch 3  MASM kernels                        [independent of 1 and 2]
   |     - q4k, q6k, moe_fused, fp16
   |     - ASM_MASM in CMake
   |     GATE: 6.4 parity, GATE-D
   |
Batch 4  Certification                       [needs 1, 2, 3]
         - GATE-B lifecycle
         - GATE-E compute-sanitizer
         - GATE-F memory
         - stub census
         GATE: 7.2-7.9
```

Batches 1, 2 and 3 have no ordering dependency on each other. Batch 3 is pure
kernel work against `QuantKernelRegistry.cpp` and can run in parallel with the
architecture work.

---

## 10. What this spec does not claim

- No statement here is a PASS. Nothing has been built or run against it.
- The 550B figure is arithmetic, not a capability. At Q4_K (~4.5 bits/weight)
  Nemotron 3 Ultra 550B-A55B is ~309 GB of weights; BF16 is ~1.1 TB. A machine
  with one consumer GPU cannot hold it. Out-of-core or sharding is a separate
  spec, and `NVMeStream.cpp` plus `VramStreamingController.cpp` are the real
  starting points.
- No valuation. The `$110M-$225M` range in prior discussion rested on
  comparables that were not verified and should not be repeated.
- No hosted-model local support. See §0.2.
