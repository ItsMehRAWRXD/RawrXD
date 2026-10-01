# RAWRXD_DEEP2_MODEL_REGISTRY_001 — Batch 3/4 receipt

AUTHORITY: `RAWRXD_SINGLE_WRITER_AUTHORITY_001`
LEASE_PID: 22344
LEASE_NONCE: 15192385244418228188
LEASE_EXPECTED_HEAD: `94cd2fadf91431b5eaf8d61e52203d1b02268263`
ACQUIRED_VIA: `staleLeaseRecovery` (all three predicates measured true)
MEASUREMENT_DATE: 2026-10-01

---

## 1. Lease provenance — no competing writer

The registry files were observed changing during the audit. **That change was this
session, under this lease.** There is no second writer.

Measured at acquisition time by the authority itself:

```ini
INCUMBENT_LEASE_PID       = 30252
INCUMBENT_PID_LIVE        = 0        (deep2_lease_holder.exe, orphaned)
INCUMBENT_EXPECTED_HEAD   = a078e3b87be6b22ed1fa6fce6a20bfdd980e4441
INCUMBENT_HEAD_MOVED      = 1        (actual HEAD 94cd2fadf)
RECOVERY_OUTCOME          = RECOVERED_AND_ACQUIRED
VALIDATE_HEAD_AT_ACQUIRE  = 1
CHECKWRITE_CMAKELISTS_OK  = 1
CHECKWRITE_FOREIGN_PATH_OK= 0        (write guard live)
```

`staleLeaseRecovery` requires all three of {older than maxAge, PID dead, HEAD
moved} and refuses otherwise. All three were measured true. No reset, checkout,
stash, clean, or deletion of foreign work was performed. The prior session's
uncommitted changes to `Deep2Engine.cpp/.h` were preserved and are still present.

---

## 2. What was implemented (verified by in-tree build + run)

`src/deep2/ModelRegistry.cpp` was a one-line `// STUB:` file. `Deep2::ModelRegistry`
was declared in `Deep2ModelRegistry.hpp` with **no definition anywhere in the build
graph**, so architecture dispatch could not fail closed — it could not run at all.

Implemented, extending the existing surfaces only:

| Item | Where | Status |
|---|---|---|
| All 7 `ModelRegistry` declarations | `ModelRegistry.cpp` | compiled + linked |
| `admit()` enforcement path | `ModelRegistry.cpp` | measured |
| `quantExecutable()` measured capability | `ModelRegistry.cpp` | measured |
| `AdmissionReject` / `AdmissionReport` / `ExecDevice` | `Deep2ModelRegistry.hpp` | extended, not replaced |
| `quantTypeId`, `presentTensors` on `ModelMetadata` | `Deep2ModelRegistry.hpp` | extended, not replaced |
| `rawrxd_deep2_model_registry` library | `CMakeLists.txt:16619` | configures + builds |
| `deep2_model_registry_admission_test` | `CMakeLists.txt:16690` | builds + runs |

### 2.1 Build gate — real build system, not an ad-hoc command line

An earlier attempt built the test green under a hand-rolled `cl` command line and
**failed under CMake** on `vulkan/vulkan.h`. That was recorded as a failure, not
papered over. Two real defects were then found and fixed:

```ini
DEFECT-1  ModelRegistry.cpp reaches QuantKernelRegistry.hpp -> GGUFLoader.hpp
          -> vulkan_compute.h. The admission gate inherits a COMPILE-TIME
          dependency on Vulkan SDK headers while deciding whether to use Vulkan.
          Fixed for now by wiring RAWR_VULKAN_INCLUDE; the underlying coupling
          is NOT removed. Logged as COUPLING-001 (Batch 6 work).

DEFECT-2  There is no `QuantKernelRegistry` CMake target in this tree. Linking
          it was silently skipped, so quantExecutable() reported false for EVERY
          format and the gate would have rejected every model — fail-closed but
          useless, and invisible in the ad-hoc build. Fixed by compiling
          QuantKernelRegistry.cpp into the registry library.
```

Final in-tree result:

```ini
CMAKE_CONFIGURE                        = PASS
BUILD rawrxd_deep2_model_registry      = PASS  (warnings only, pre-existing)
BUILD deep2_model_registry_admission_test = PASS
RUN   deep2_model_registry_admission_test = PASS  exit 0
BUILD_SYSTEM                           = Visual Studio 17 2022, Release
```

### 2.2 Admission gate — measured output

Binary: `d2cfg/bin/Release/deep2_model_registry_admission_test.exe`.
Every gate field is derived from a counter incremented only when its assertion held.

```ini
DENSE_ADMITTED=1        MOE_ADMITTED=1        SSM_ADMITTED=1
HYBRID_ADMITTED=1       MLA_ADMITTED=1

UNKNOWN_ARCH_REJECTED=1
NAME_GUESSING_REJECTED=2
MISSING_TENSOR_REJECTED=1
UNSUPPORTED_QUANT_REJECTED=1
MALFORMED_METADATA_REJECTED=3
UNSUPPORTED_OPERATOR_REJECTED=1
UNREGISTERED_ARCH_REJECTED=1
COLLISION_SAFE=1

QUANT_Q8_0_CPU_EXECUTABLE=1     QUANT_BF16_CPU_EXECUTABLE=1
QUANT_IQ2M_CPU_EXECUTABLE=0     QUANT_Q8_0_GPU_EXECUTABLE=0

ADMISSION_SUITE_VERDICT=PASS
```

---

## 3. Batch 3 gate block — HONEST STATUS

```ini
MODEL_REGISTRY_IMPLEMENTED             = PASS
MODEL_REGISTRY_CALLED_BY_LOADER        = PASS   <-- proven at runtime, see §3.1
UNKNOWN_ARCH_FAIL_CLOSED               = PASS   (unit test; see §3.2 caveat)
MISSING_REQUIRED_TENSOR_REJECTED       = PASS   (unit test)
UNSUPPORTED_QUANT_REJECTED             = PASS
UNSUPPORTED_OPERATOR_REJECTED          = PASS
MOE_METADATA_CLASSIFICATION            = PASS
SSM_METADATA_CLASSIFICATION            = PASS
HYBRID_METADATA_CLASSIFICATION         = PASS
STUB_TU_CENSUS_COMPLETE                = PASS
IN_BUILD_STUBS_UNACCOUNTED             = 0
```

### 3.1 MODEL_REGISTRY_CALLED_BY_LOADER — runtime evidence

`Deep2Engine::loadModel` now builds `Deep2::ModelMetadata` from values it already
parsed, populates `presentTensors` from `loader->listTensors()`, and calls
`ModelRegistry::admit(...)`. The call sits after all geometry is parsed and after
the final-norm/LM-head topology check, but BEFORE the per-layer weight bind loop,
so a model that must be rejected is rejected before the expensive work.

Production `Architecture` descriptors are registered from the engine TU, bound to
the real engine members (`forwardTokenAllLayers`, `reset`, `unloadModel`,
`loadModel`) — not test fixtures.

Measured on a real model, `qwen2.5-coder-1.5b-base.gguf` (940 MB, 338 tensors):

```text
[Deep2Engine] admission OK arch=qwen2 family=GENERIC_TRANSFORMER moe=0 mla=0
              recurrent=0 slidingWindow=0 quant=Q6_K(type 14) tensors=338
PROBE_LOAD_OK=1
PROBE_ARCH=qwen2
LOADER_ADMISSION_REACHED=PASS
LOADER_ADMISSION_OUTCOME=ADMITTED
LOADER_ADMISSION_VERDICT=PASS
```

Build chain: `InferenceEngine.lib` compiles and links with `ModelRegistry.cpp`
added to `INFERENCE_ENGINE_SOURCES` (CMakeLists.txt:4416). The
`rawrxd_deep2_model_registry` static lib is deliberately NOT linked into
`InferenceEngine` — it also carries `QuantKernelRegistry.cpp`, which
`InferenceEngine` already compiles, so linking both would duplicate symbols.

### 3.2 Caveat — loader-level negative case NOT obtained

I attempted a real-GGUF negative test by copying the model and overwriting the
`general.architecture` value with an unknown same-length tag. The copy was
rejected by `GGUFLoader` at `GGUFLoader.hpp:744` ("invalid GGUF metadata entry")
BEFORE admission ran, because the byte offset was off by one and the metadata
walk desynced. Verified afterwards that the original model file is unmodified.

Consequences, stated plainly:

- The loader-level negative is **unproven**. The rejection happened at GGUF
  parse, not at admission.
- There is no architecture whitelist in `GGUFLoader.hpp`; the
  `UnknownArchitecture` branch is reachable in principle but was not exercised
  end-to-end.
- All six admission negative cases (unknown arch, no parsed arch, missing tensor,
  unsupported quant, malformed geometry, SpecialGraph, recognized-but-unimplemented)
  remain proven in `deep2_model_registry_admission_test`, which runs the real
  `ModelRegistry` code.

### 3.3 Defects found and fixed during loader wiring

```ini
DEFECT-3  Required-tensor role matcher used the stem-first spelling
          "attn_q.0.weight". Deep2Engine::loadModel binds the real GGUF layout
          "blk.0.attn_q.weight" (Deep2Engine.cpp:1202-1208). The admission gate
          would have rejected EVERY real model, and the unit test passed only
          because its fixture used the same wrong convention. Role matcher now
          accepts blk.<n>.<stem>.weight, <stem>.<n>.weight, and blk.<n>.<stem>;
          fixtures were rewritten to the real layout and still pass.
DEFECT-4  ModelRegistry.cpp was absent from INFERENCE_ENGINE_SOURCES, so
          admission would have failed to link. Added.
```

### 3.4 Observations

- `PROBE_REGISTERED_ARCHITECTURES=0` when queried BEFORE the first `loadModel`,
  because registration is a function-local static inside `loadModel` rather than
  a file-scope initializer. Registration does precede `admit()` on every call, so
  behaviour is correct; the ordering is noted because a static-init-time
  registration would make the registry queryable earlier.
- `rawrxd/src/authority/SingleWriterAuthority.cpp` shows as modified in
  `git status`. That is a PRE-EXISTING foreign modification, not made by this
  batch, and it is outside this lease's authorized paths. It was not touched.

---

## 4. Measured quant capability (replaces "BF16 passes because it parses")

Read from `QuantKernelRegistry.cpp` `RegisterBuiltins()` and verified at runtime.
This is the distinction the contract requires:

```ini
# CPU-executable (dequant AND gemv really registered)
F32 F16 BF16 Q4_0 Q4_1 Q5_0 Q5_1 Q8_0 Q2_K Q3_K Q4_K Q5_K Q6_K Q8_K

# Parseable in the GGML type enum, NOT executable
IQ*  -> RegisterIQKernels() {} is an empty stub (QuantKernelRegistry.cpp:68)
F16 GEMV -> Deep2_FP16_GEMV is a stub that memset()s its output to zero and
            prints [WARN] (QuantKernelRegistry.cpp:71-76)

# GPU
QUANT_*_GPU_EXECUTABLE = 0 for all — no Vulkan-side kernel registration is
                         observable from the CPU registry, so GPU quant
                         capability is reported FALSE rather than inferred.
```

BF16 passes CPU admission because `dequant_bf16` + `gemv_bf16_scalar` are genuinely
registered — measured, not assumed. It is reported false for GPU.

---

## 5. Structural findings that constrain Batches 4–9

These are measured, and they change what Batches 4–9 can honestly claim.

### FINDING-A — the metadata producer is a prebuilt binary

```ini
src/deep2/GGUFLoader.hpp        34070 b   (rich interface)
src/deep2/GGUFLoader.cpp           35 b   // STUB: src/deep2/GGUFLoader.cpp
src/deep2/KVCache.h              8239 b
src/deep2/KVCache.cpp              32 b   // STUB
src/deep2/ModelLoader.cpp          36 b   // STUB
src/deep2/UniversalModelLoader.cpp 45 b  // STUB  (no .hpp exists at all)
```

CMake names **none** of these four .cpp files in any target. Meanwhile
`Deep2Engine.cpp:839` calls `loader->load()` and `loader->error()`.

The real GGUF parsing therefore lives in a prebuilt blob:
`rawrxd/build/Release/InferenceEngine.lib` (49,232,062 b),
`InferenceEngine_patched.lib` (44,313,158 b), and four other copies.

**Consequence:** every field Batch 4 admission consumes — `numExperts`,
`ssmInner`, `numKVHeads`, `presentTensors` — is produced by a binary with no
auditable source in this tree. Admission can be *correct* and still be fed
unverifiable inputs. Any Batch 4/5 claim about "parsed metadata" is a runtime
observation, not a source-verifiable property.

This is also why `UniversalModelLoader` does not exist: the chain in the batch plan
(`ModelRegistry.cpp -> UniversalModelLoader -> resolve(metadata)`) names a TU that
is a stub with no header. Admission must be wired into the real load path inside
`Deep2Engine.cpp`, not into `UniversalModelLoader`.

### FINDING-B — no tool-dispatch authority for Batch 9

Four non-stub tool-authority surfaces coexist:

```ini
src/core/ToolRegistry.cpp              11327 b
src/tools/ToolRegistryAuthority.cpp     1964 b
src/deep2/AgentToolAuthority.cpp        1578 b
src/deep2/AgentToolRegistry.hpp        17915 b
src/agentic/ToolRegistry.cpp             690 b
src/agentic/AgentToolHandlers.cpp         28 b   // STUB
src/agentic/RawrXD_ToolRegistry.cpp       30 b   // STUB
```

`DUPLICATE_KERNEL_AUTHORITY=0` is not currently satisfied for tool dispatch. Batch 9
cannot be written as "wire the bridge" until one of these is designated authoritative;
that is a decision, not a patch, and it is not this batch's call to make silently.

### FINDING-C — six false-success executables already exist

`test_o_proj_gemv`, `test_o_proj_mulmat_002`, `test_v_proj_parity`,
`test_attn_out_bisect`, `test_gguf_alignment_diagnostic`,
`Deep2Engine_RouterSmokeTest` are `int main(){ return 0; }` and are wired with only
`if(TARGET InferenceEngine)` — no `option(... OFF)`. They build and exit 0 by
default. `FALSE_SUCCESS_PATHS=0` is therefore already violated before Batch 13.
Full detail in STUB_CENSUS.md §3.

---

## 6. Files changed this batch

```ini
M rawrxd/CMakeLists.txt
A rawrxd/src/deep2/ModelRegistry.cpp          (was 1-line STUB)
M rawrxd/src/deep2/Deep2ModelRegistry.hpp     (extended only)
A rawrxd/tools/deep2_model_registry_admission_test.cpp
A rawrxd/audit/RAWRXD_DEEP2_MODEL_REGISTRY_001/STUB_CENSUS.md
A rawrxd/audit/RAWRXD_DEEP2_MODEL_REGISTRY_001/RECEIPT.md
```

All within the lease's 13 authorized paths. No commit made. No file deleted.
No prior session's work reverted.

---

## 7. RAWRXD_DEEP2_BATCH5_CANONICAL_INFERENCE_001 — PASS (runtime)

Driven through `deep2_canonical_inference_probe`, which links `InferenceEngine` and
uses only production primitives: `loadModel`, `tokenize`, `generateStream`,
`initializeDecodeCursor`, `decodeContinuousOne`, `sampleCommittedToken`.
No synthetic forward. No fixture architecture.

Model: `F:/~dev/qwen2.5-coder-1.5b-base.gguf` (940 MB, Q6_K, 338 tensors,
hidden=1536, layers=28, heads=12, kv_heads=2, vocab=151936).

```text
MODEL_LOADED=1              TOKENIZER_READY=1        PROMPT_TOKEN_COUNT=5
STREAM_STATUS=Completed     STREAM_COMPLETED=1        STREAM_CANCELLED=0
STREAM_GENERATED_TOKENS=8   STREAM_CALLBACK_TOKENS=8  STREAM_TOKENS_OUT_OF_VOCAB=0
STREAM_FAILURE_DETAIL=(none)
[STREAM] RESULT generated=8 promptTokens=5 prefillMs=6481.2 decodeMs=9990.0
          tps=0.80 cancelled=0 completed=1 status=0

DECODE_0_OK=1  DECODE_0_TOKEN=113799  DECODE_0_SEQ=1  DECODE_0_ROUTE=1(Cpu)
LOGITS_EXAMINED=151936  LOGITS_NONFINITE=0
LOGITS_MIN=-14.679391   LOGITS_MAX=12.767042   LOGITS_FINITE=1
TOKEN_ID_VALID=1

REAL_GGUF=1  REAL_WEIGHTS=1  REAL_FORWARD=1  GENERATED_TOKEN_COUNT=8
CANONICAL_INFERENCE=PASS
```

Ground-truth check on the decoded output, prompt "The capital of France is":

```text
STREAM_TEXT=[ Paris. The capital of France is also]
```

Coherent, grammatical, factually correct, and continuing the prompt's own frame.
A fake-logits path cannot produce this. `FAKE_LOGITS=0`.

```ini
BATCH_5_CANONICAL_INFERENCE=PASS
REAL_GGUF=1   REAL_WEIGHTS=1   REAL_FORWARD=1
LOGITS_FINITE=PASS             GENERATED_TOKEN_COUNT=8
STUB_FALLBACKS=0              HOST_FAKE_FORWARD=0
```

### 7.1 Defect found by this batch, and its true cause

First run reported `cpu_forward_exception` and
`STREAM_FAILURE_DETAIL=prefill forward failed at token 0`, with the underlying
exception `attention: sequence/KV position mismatch`.

Root cause was **the probe, not the engine**. The first version of the probe drove
`decodeContinuousOne` BEFORE `generateStream`. That advanced
`kvCache->currentLength()` past 0, so `generateStream`'s prefill then began with a
non-zero KV position while passing `seqLen = p+1 = 1` — a genuine caller-side KV
mismatch. Reordering the probe so the stream runs first on an untouched cache, and
running the decode measurement on a SECOND engine instance, made the failure
disappear.

This is recorded because it is the same defect class the earlier lifecycle findings
described ("generation #1 works, generation #2 inherits stale state"), and it
demonstrates the probe is sensitive to it rather than immune to it.

A second probe error was also corrected: `forwardSpeculativeBlock` was initially
used as "prefill". It is a speculative-decode primitive that requires
`kvCache->currentLength() >= basePos+count` (`Deep2Engine_Speculative.cpp:340`), so
it cannot prefill a fresh cache. The canonical primitive is `decodeContinuousOne`.

### 7.2 Scope note

Four geometry read accessors were added to `Deep2Engine.h`
(`hiddenDim()`, `vocabSize()`, `numLayers()`, `headDim()`). `modelWeights` is
private, and without these the gate would have had to guess buffer sizes or skip
the finiteness measurement. They are read-only views of already-parsed metadata and
introduce no new state.