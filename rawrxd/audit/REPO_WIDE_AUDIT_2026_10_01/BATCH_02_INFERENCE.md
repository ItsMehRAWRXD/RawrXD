# BATCH 02 — RawrXD Inference Chain Audit

- **Repository:** `F:\~dev\rawrxd`
- **HEAD:** `9f67682ffea12a182ae4fd2d41fb3bc524f61d2b`
- **Tree state:** dirty (193 modified/untracked paths) — audit is of the **working tree**, not git
- **Scope:** inference chain end to end, stages 1–9
- **Method:** source reading + **direct measurement** (built and executed production code paths)

## Runtime evidence basis

The binary `build\bin\Release\rawr-server.exe` (1,697,280 B, mtime 2026-10-01 18:16) was
started against three real GGUF models and driven over HTTP. **Note the binary self-reports
`build_git_sha=7d2fc86e3dec`, which is not HEAD `9f67682f`**, and `source_dirty=true`. The
binary is therefore evidence of *a* build of this tree, not of the working tree exactly.

Measurement harnesses built for this audit (in `%TEMP%\kilo\b02`, linking production sources
directly, no stubs):

| Tool | Links | Purpose |
|---|---|---|
| `kqparity.exe` | `kquant_parity_check.cpp` + `src/gguf_loader.cpp` | re-run the AVX-512 Q4_K parity gate |
| `selfchk.exe` | `src/deep2/QuantKernelRegistry.cpp` | registered GEMV vs registered dequantizer, real weights |
| `probe2.exe` | `src/deep2/GGUFLoader.hpp` | tensor-type census + geometry, real models |
| `rms.exe` | `src/deep2/QuantKernelRegistry.cpp` | decoded weight RMS sanity |

---

## Per-stage findings

| Stage | Classification | Evidence (file:line) | Finding |
|---|---|---|---|
| **1. GGUF parser / header / metadata** | **VERIFIED** | `src/deep2/GGUFLoader.hpp:714` (`loadOneShard`), `:723-731` magic/version/limit checks, `:644-651` bounded metadata reads, `:754-785` tensor descriptors, `:799-803` overflow-guarded range validation; `src/gguf_loader.cpp:622-699` second parser | Two independent, genuinely real parsers. `Deep2::GGUFLoader` is mmap-based, shard-aware, and fails closed on every length-prefixed field. Verified live: probed 3 real models, 201/239/113 tensors parsed with correct per-tensor byte sizes. |
| **2. Tensor binding / weight layout** | **IMPLEMENTED_NOT_RUNTIME_VERIFIED** | `src/deep2/Deep2Engine.cpp:1222-1254` (`bindTensor`, GGUF `shape[0]`=width, overflow-checked row product), `:1256-1262` (`bindFirst` alias fallback), `:1265-1289` geometry cross-check | Real binding with fail-closed geometry validation. Confirmed correct geometry at runtime (hidden 2048 / 22 layers / 32 heads / 4 kv_heads / headDim 64 / FFN 5632 for TinyLlama). **But the composed forward pass is numerically wrong for Q4_K (see Top Defect #1), so the binding+layout result cannot be called verified.** |
| **3. Quant kernels Q4_K / Q6_K / Q4_0 / Q8_0 / Q5_K** | **VERIFIED** | `src/deep2/QuantKernelRegistry.cpp:593` (`gemv_q4_k_scalar`), `:922` (`gemv_q6_k_scalar` → `:507 quantize_row_q8_K` + `:876 vec_dot_q6_K_q8_K`), `:952` (`gemv_q4_0_scalar`), `:398` (`gemv_q8_0_scalar`), `:1742` (`gemv_q5_k_scalar`); `src/gguf_loader.cpp:288,333,173` dequantizers | All five types are real arithmetic. **Measured directly against real model weights** (`selfchk.exe`): registry GEMV vs registry dequantizer on `blk.0.attn_q.weight` (Q4_K) → cosine **0.997194**, max relerr 0.124; on `blk.0.attn_v.weight` (Q6_K) → cosine **0.999925**, max relerr 0.0069. Decoded weight RMS 0.0129 (Q4_K) / 0.0090 (Q6_K) — physically plausible. The kernels are **not** the source of the garbage output. |
| **4. CPU GEMV/GEMM dispatch + feature detection** | **VERIFIED** | `src/deep2/QuantKernelRegistry.cpp:109-124` (`ProbeCPU`, real `CPUID`/`CPUIDEX` bit tests), `:1900-1990` (`RegisterBuiltins`), `:1939` AVX-512 admission, `:1172-1185` AVX-512 Q4_K dispatch; `src/deep2/k_quant_gemv_avx512.h:126` (`GemvQ4K_AVX512`); `src/deep2/Deep2Engine.cpp:910` (`Initialize()` in `initialize()`), `:3473` (`GetGEMV` from `LinearW`) | Real CPUID feature detection, real dispatch table, real reachability from the live path. Runtime log confirms: `AVX512F=1 … Registered 14 GEMV kernels`. **`QuantKernelRegistry.cpp` compiles clean under `/arch:AVX512` at this HEAD** (verified with MSVC 19.44) — the recorded build break at `k_quant_gemv_avx512.h:264` is **not reproducible**; line 264 is a comment. |
| **5. Vulkan compute path** | **IMPLEMENTED_NOT_RUNTIME_VERIFIED** | `src/deep2/vulkan_compute.cpp:567-579` (`shaderPath` search), `:668-698` (`createPipelineFromFile` per shader), `:708-736` (`DispatchGemvQ4KBatch8Row`, real descriptor set + push constants + `vkCmdDispatch`), `:2941`; `src/deep2/shaders/*.spv` (9 files, all verified magic `0x07230203`) | Real Vulkan: 9 valid SPIR-V modules with `.comp` sources, real pipeline creation, real dispatch. **No GPU runtime evidence gathered in this audit** (server run used CPU; log shows `vulkan=0/0`). Also carries two dead-path defects — see Top Defects #2 and #3. |
| **6. RoPE / KV cache / attention** | **IMPLEMENTED_NOT_RUNTIME_VERIFIED** | `src/deep2/Deep2Engine.cpp:3567-3639` (`applyRoPE`, both NeoX and GPT-J conventions, fail-closed on unbound theta), `:4160-4195` (real `double` dot, real `softmax`, real value mix), `:4109-4113` KV cache write; `src/deep2/KVCache.h:35,155,177` (real inline alloc/pointers) | Real computation with no stubs. `KVCache.cpp` is a 32-byte stub but `KVCache.h` carries the full inline implementation, so this is harmless — the `.cpp` is a dead TU. **Not runtime-verified: the Q4_K forward pass degenerates downstream of this stage.** |
| **7. Final norm + LM head + logits** | **IMPLEMENTED_NOT_RUNTIME_VERIFIED** | `src/deep2/Deep2Engine.cpp:2990` (`RMSNormW` on `finalNorm`), `:3014` (`LinearW` on `lmHead` → vocab), `:3035-3036` finite check, `:3040-3057` (`computeLogitsBatch`); `src/deep2/Deep2Engine.cpp:3516` (`RMSNormW`) | Real. LM head confirmed bound at runtime as Q6_K `output.weight` shape [2048, 32000]. **Not runtime-verified end-to-end for Q4_K.** |
| **8. Sampling + token generation loop** | **VERIFIED** | `src/deep2/Deep2Engine.cpp:5101-5230` (real prefill + decode loop), `:5602-5741` (`generateStream` with `completed == (status == Completed)` invariant and `abort()` on violation at `:5704-5714`), `:3206-3256` (`configureGeneration` sampler binding); `src/deep2/Sampler.cpp:83` (`categoricalDraw` with xorshift64 RNG), `:180-257` (`CombinedSampler`, real top-k → top-p → min-p) | Real loop, real RNG, correct result contract. Runtime: 40/40 and 24/24 tokens generated, `completed=1 status=0`, 2.78 TPS, correct token accounting. `TemperatureSampler`/`TopKSampler` (`Sampler.cpp:20,44`) are **dead and defective** (Top Defect #5). |
| **9. Server exposure (rawr-server, OpenAI routes)** | **VERIFIED** | `src/deep2/deep2_openai_server.cpp:504` (`/v1/models`), `:545` (`/v1/chat/completions`), `:548-563` bearer-token auth, `:573-580` fail-closed 503 when no model, `:633,691` → `Deep2Engine::generateStream`; `:381,385` engine binding | Real HTTP server, real routes, real auth, real streaming/non-streaming. Verified live: `/health` returns real build identity; `/v1/chat/completions` returns 200 with real content on a Q2_K model. Model admission fails closed correctly (`phi3-mini-Q2_K` rejected with `MODEL ADMISSION REJECTED … field=attn_q`). |

---

## TOP DEFECTS

### 1. CRITICAL — Q4_K forward pass produces degenerate text; the whole chain "succeeds" while returning garbage

`src/deep2/Deep2Engine.cpp:2975` (logits) / `:3358` (LinearW) / `:3901` (attention)

Reproduced twice against TinyLlama-1.1b-chat-v1.0.Q4_K_M, `temperature=0`, greedy:

```
prompt "Say exactly: RAWRXD_B02_E2E_OK"  ->  "friquefriquefrique…" x40
prompt "What is the capital of France?"   ->  "friquefriquefrique…" x24
finish_reason=stop   completion_tokens=40   prompt_tokens=30
```

HTTP 200, correct token counts, `completed=1`, `status=0` — a **structurally perfect false success**.

The same binary on a Q2_K model is coherent:

```
llama3.2-3b-Q2_K: "What is the capital of France?" -> "France, I ask?"
```

**Localization result (negative, and important):** the quant kernels are *not* the cause.
`selfchk.exe` on real weights gives GEMV-vs-dequant cosine 0.997194 (Q4_K) and 0.999925
(Q6_K), with plausible weight RMS. The kquant parity gate re-run clean:
`RESULT PASS (0 failures), 20 checks`. Tensor-type census:

```
TinyLlama Q4_K_M : F32=45  Q4_K=135  Q6_K=21
llama3.2-3b Q2_K : F32=58  Q2_K=112  Q3_K=84  Q6_K=1
```

So the divergence is **not** a Q6_K-count effect and **not** a GEMV defect. The fault lies in
one of the composition stages for the Q4_K geometry (H=2048, 22 layers, 32 heads, 4 kv_heads,
headDim=64, GQA group 8, FFN 5632) — most likely Stage 2 layout mapping or Stage 6/7
assembly — and it is **not** localized by this batch. Any receipt claiming a passing
end-to-end Q4_K decode is unfounded.

### 2. HIGH — Vulkan speculative-accept pipeline is resolved, logged, and never created

`src/deep2/vulkan_compute.cpp:653` resolves `deep2_spec_accept.spv` and `:665` prints it in
`[SHADER_PATH] … ac=<path-or-NOTFOUND>`, implying it loaded. But `createPipelineFromFile` is
called for `ops/q/qb/q4r/q8r/am/so/sa` (`:669-698`) and **never for `ac`**.
`specAcceptPipeline_` therefore stays `VK_NULL_HANDLE`, so:
- `src/deep2/vulkan_compute.cpp:7019` — `RunSpecAcceptPrefix` returns false at its guard
- `src/deep2/vulkan_compute.cpp:7062` — `RunSpecAcceptPrefixResident` returns false at its guard

Both are additionally **orphaned**: grep across the tree finds **zero callers** outside their own
definitions and the `vulkan_compute.h:983,986` declarations. Doubly dead, while the startup
trace actively reports the shader as resolved.

### 3. HIGH — 94 cert/gate/parity files in `src/deep2` are empty stubs; 4 are still in the build

Every one of these is a 32–48 byte `// STUB:` file:

```
src/deep2/deep2_gpu_q4k_gemv_cert.cpp      (48 B)   CMakeRefs=1
src/deep2/deep2_gpu_q6k_gemv_cert.cpp      (48 B)   CMakeRefs=1
src/deep2/deep2_parity_cert.cpp            (42 B)   CMakeRefs=1
src/deep2/test_q4k_gemv_parity.cpp         (45 B)   CMakeRefs=1
src/deep2/deep2_k2_logits_climb_cert.cpp   CMakeRefs=1
… 94 total
```

These compile into the target and contribute nothing. `deep2_gpu_q4k_gemv_cert.cpp` and
`deep2_gpu_q6k_gemv_cert.cpp` are precisely the filenames that read as GPU quant
certification evidence. **A gate whose file exists, is in CMake, and contains no measurement
is worse than an absent gate**, because it satisfies an existence check. The 94-file list is
at `audit/REPO_WIDE_AUDIT_2026_10_01/_b02_tiny_files.txt`.

### 4. HIGH — 584 source files under 120 bytes; the primary implementation `.cpp` for six named subsystems is a stub

`src/deep2/GGUFLoader.cpp` (35 B), `src/deep2/KVCache.cpp` (32 B), `src/deep2/NUGemv.cpp`
(31 B), `src/deep2/IQQuantKernels.cpp` (39 B), `src/engine/sampler.cpp` (33 B),
`src/inference/Deep2Engine.cpp` (40 B) — all `// STUB:`. The real logic survives only because
it was moved into `.hpp`/other paths. Any build, grep, or existence check keyed on these
`.cpp` names is answering about an empty translation unit.

Repo-wide: **139 files are exactly the 24-byte string `// Auto-generated stub`**, and
`CMakeLists.txt` contains **1,836 `# AUTO-REMOVED: stub file` markers**.

### 5. MEDIUM — `TemperatureSampler` and `TopKSampler` compute a distribution, then discard it

`src/deep2/Sampler.cpp:26-41` computes `probs[i] = exp((logits[i]-maxL)/temp)`, normalizes,
then returns `argmax`. Argmax over a temperature-scaled softmax is **identical to argmax over
the raw logits** for any `temp > 0`, so `temperature` has no effect. `Sampler.cpp:44-71`
(`TopKSampler`) has the same shape: the softmax-then-argmax reduces to top-1 of top-k, so
`topK` also has no effect. Both are **currently dead** (only instantiated in
`Deep2Engine.cpp.archpack_*.bak`, never in the live `Deep2Engine.cpp:3236/3240`), so the
product path is unaffected — but they are live, exportable, plausible-looking classes that
cannot do what their names and signatures promise.

### 6. MEDIUM — Recorded build break is not reproducible at HEAD

`AGENTS.md` states `k_quant_gemv_avx512.h:264` assigns `__m512` to `__m512i`, "blocking the
`InferenceEngine` target". At `9f67682f` line 264 is a **comment**, and
`QuantKernelRegistry.cpp` compiles clean with `cl /arch:AVX512` (MSVC 19.44.35228, verified
this batch). Either the defect was fixed without the ledger being updated, or the recorded
build used a different source identity. Treat the claim as stale and re-derive it.

### 7. MEDIUM — Nine distinct `GGUFLoader` classes; only one is bound to the product path

`src/gguf_loader.hpp:149` (`rawrxd::GGUFLoader`, real, 977-line `.cpp`),
`src/deep2/GGUFLoader.hpp:101` (`Deep2::GGUFLoader`, real, bound to `Deep2Engine.cpp:1185`),
plus `src/core/gguf_loader.h:77`, `src/core/local_gguf_loader.hpp:154`,
`src/core/model_loader_production.cpp:22`, `src/core/gguf_loader_production.cpp:262`,
`src/core/NativeGGUFLoader.h:19`, `src/core/model_loader_chunked_bridge.cpp:18`,
`src/model_source_resolver.h:21`. Two are real; seven are alternates. `Deep2ArchitectureRuntime.hpp:197`
dispatches to `QuantKernelRegistry::GetDequant` via a *third* path (`UniversalTensorProxy`),
so there is no single owner of "how a GGUF tensor becomes a matrix".

### 8. MEDIUM — Five MASM GEMV wrappers defined, never registered

`src/deep2/QuantKernelRegistry.cpp:166` (`gemv_q4_k_masm`), `:199`, `:223`, `:235`, `:247`.
Each has exactly **one** occurrence in the file — its own definition. `RegisterBuiltins`
(`:1900-1990`) never selects any of them. The corresponding MASM providers and the
`Sovereign_Q4K_GEMV_AVX2_V2` / `Deep2_Q6_K_GEMV` externs (`:131-153`) are linked-or-not with
no live caller. Dead weight that reads as an active optimized path.

### 9. LOW — 283 CMake-referenced source files do not exist, including inference-adjacent ones

Of 890 `src/*.cpp` entries matched in `CMakeLists.txt`, **283 are absent**, e.g.
`src/serve/inference_plugin_backend.cpp`, `src/serve/rawrxd_pipe_server.cpp`,
`src/serve/rawrxd_serve_inference_plugin.cpp`, `src/llm_adapter/ggufrunner_link_fallbacks.cpp`,
`src/lsp/RawrXD_LSPServer.cpp`, `src/win32app/Win32IDE_GGUFInspector.cpp`. Any target that
lists these cannot configure/build. `src/win32app/*` is the largest hole (per the batch
brief, ~225 files).

### 10. LOW — `kquant_parity_check`'s headline check is intra-header, not against production

`kquant_parity_check.cpp:278` compares `GemvQ4K_AVX512` against `GemvQ4K`, and **both are
defined in the same file** (`src/deep2/k_quant_gemv_avx512.h`) and share
`UnpackQ4KScales` and the same group rule. A shared misreading of the GGUF Q4_K layout cancels
out and the check passes. The independent-reference checks (`:94 RefGemvQ4K_ggml`, and the
loader cross-check at `:127`) are sound, which is why it still has value — but
"AVX512 vs scalar direct agreement" does **not** test the production `gemv_q4_k_scalar` in
`QuantKernelRegistry.cpp:593`, which is what non-AVX512 hosts run. Verified independently in
this batch via `selfchk.exe` (cosine 0.997194), so the kernel is fine — the *gate* just does
not cover it.

---

## What is genuinely real

For balance, and because the audit should not only subtract:

- `Deep2::GGUFLoader` is a well-engineered mmap parser: bounds-checked on every
  length-prefixed field, overflow-guarded, shard-aware, alignment-validating, fail-closed.
- `QuantKernelRegistry` is a real dispatch layer with real CPUID probing, real scalar/AVX2/AVX-512
  kernels, real `static_assert`s on block geometry, and correct fail-closed registration policy
  (Q5_K and Q3_K vector paths deliberately kept unregistered with the reasons written down).
- `Deep2Engine::generateStream` enforces its result contract structurally and calls `abort()` on
  violation rather than logging and continuing. The D1/D2 lifecycle repairs are real.
- `phi3-mini-Q2_K` is **rejected at admission** with a named field, rather than loading into a
  half-bound state.
- `/v1/chat/completions` enforces bearer auth, returns 400/401/503 appropriately, and resets the
  KV cache per request.

---

## BATCH 02 STATUS

**PARTIAL**

Stages 1, 3, 4, 8, 9 are **VERIFIED** by direct execution. Stages 2, 5, 6, 7 are
**IMPLEMENTED_NOT_RUNTIME_VERIFIED**. No stage in this batch is UNIMPLEMENTED or
DEAD/UNBOUND as a *chain* stage — the chain is real and reachable end to end.

The batch does **not** close, because of Top Defect #1: the inference chain is demonstrably
reachable, demonstrably executes, and demonstrably returns **non-linguistic garbage** on a
real Q4_K model while reporting complete success at every layer of the result contract. That
is the specific failure mode this audit exists to catch, and the quant kernels were positively
cleared rather than blamed. The next batch must localize it across stages 2/6/7 for the
H=2048 / 22-layer / GQA-8 geometry, and the Q4_K end-to-end decode must be treated as
**unverified** until a real model produces real text.
