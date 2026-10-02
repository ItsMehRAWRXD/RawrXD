# RAWRXD_AUTHORITY_CLOSURE_AUDIT_001

Source-only audit of `RAWRXD_*_AUTHORITY_001` claims against the filesystem.
No build, no runtime, no generation. Every statement below is a filesystem or
source measurement.

## 0. The rule this audit applies

An authority name in a ledger is a **claim**, not an implementation. The
strongest state actually supported is the one that gets recorded:

```
DOCUMENTATION_ONLY   name appears only in prose/ledger files
PLAN_ONLY            name appears only in a plan, possibly UNIMPLEMENTED_STUB
SOURCE_DECLARED      a header declares it
SOURCE_IMPLEMENTED   a .cpp exists with a real, non-stub body
CMAKE_WIRED          some target compiles that .cpp
BINARY_REACHABLE     the symbol survives into a linked binary
RUNTIME_PROVEN       a receipt exists generated from a production path
RETRACTED            previously claimed, then withdrawn
UNIMPLEMENTED_STUB    file is a `// STUB` placeholder
STALE_CLAIM          the named artifact does not exist at all
```

## 1. Name census

```text
UNIQUE_AUTHORITY_NAMES = 112
TOTAL_REFERENCE_SITES  = 705
```

Of the names appearing **only** in documentation with zero source and zero
CMake occurrences, the compute block is the densest cluster:

```text
RAWRXD_COMPUTE_STAGE_AUTHORITY_001     RAWRXD_LINEARW_AUTHORITY_001
RAWRXD_TENSOR_COMPUTE_AUTHORITY_001    RAWRXD_MOE_COMPUTE_AUTHORITY_001
RAWRXD_ATTENTION_COMPUTE_AUTHORITY_001 RAWRXD_SSM_COMPUTE_AUTHORITY_001
RAWRXD_QUANT_KERNEL_AUTHORITY_001      RAWRXD_RMSNORM_COMPUTE_AUTHORITY_001
RAWRXD_FFN_COMPUTE_AUTHORITY_001       RAWRXD_ROPE_COMPUTE_AUTHORITY_001
RAWRXD_LAYER_COMPUTE_AUTHORITY_001     RAWRXD_SAMPLER_COMPUTE_AUTHORITY_001
RAWRXD_SPECULATIVE_COMPUTE_AUTHORITY_001 RAWRXD_COMPUTE_CACHE_AUTHORITY_001
RAWRXD_COMPUTE_SKIP_AUTHORITY_001      RAWRXD_COMPUTE_MEMORY_AUTHORITY_001
RAWRXD_CPU_THREAD_AUTHORITY_001        RAWRXD_CPU_GEMV_AUTHORITY_001
RAWRXD_GPU_RESIDENCY_AUTHORITY_001      RAWRXD_GPU_TRANSFER_AUTHORITY_001
RAWRXD_DUAL_GPU_COMPUTE_AUTHORITY_001   RAWRXD_VULKAN_COMPUTE_AUTHORITY_001
```

These names do not exist as source identifiers. They exist only because the
ledger asserts them.

## 2. `src/compute/` — files exist, nothing compiles them

```text
src/compute exists   = YES
files                = 42  (21 .cpp + 21 .h)
STUB markers         = 0
total .cpp lines     = 1422
```

So the bodies are **real**, not placeholders. `TensorComputeAuthority.cpp`
contains genuine state tracking (per-tensor name, rows, cols, size, backend,
kernel). That part of the claim holds.

The closure then fails completely:

```text
CMakeLists.txt references to "src/compute"  = 0
glob directives that could cover src/compute  = 0   (globs exist only for
                                                  src/ui/*.cpp, src/asm/*.asm,
                                                  MSVC roots, Vulkan SDK dirs)
references to these headers from outside
  src/compute                                = 0
```

**Consequence:** all 42 files compile into nothing, into no binary, and are
called by nothing. Their strongest supported state is `SOURCE_IMPLEMENTED`.
Not `CMAKE_WIRED`. Not `BINARY_REACHABLE`. Not `RUNTIME_PROVEN`.

Several are also **dead duplicates** of symbols that already exist and are
wired elsewhere in the tree:

| symbol | hits in `src/compute` | hits elsewhere in repo |
|---|---|---|
| `validateTensor` | 1 | **5** |
| `resolveKernel` | 1 | **2** |
| `beginLayer`    | 1 | **11** |
| `computeQKV`    | 1 | **0** (dead-only) |

## 3. Five claimed compute authorities do not exist

Checked one by one against the filesystem, as claimed in the ledger's
"Direct-call map":

| claimed file | .h | .cpp | state |
|---|---|---|---|
| `ComputeRouteAuthority` | **absent** | **absent** | STALE_CLAIM |
| `ComputeStageAuthority` | **absent** | **absent** | STALE_CLAIM |
| `LinearWAuthority` | **absent** | **absent** | STALE_CLAIM |
| `KernelDictionaryAuthority` | **absent** | **absent** | STALE_CLAIM |
| `ForwardPassAuthority` | **absent** | **absent** | STALE_CLAIM |
| `TensorComputeAuthority` | 804 B | 3859 B | SOURCE_IMPLEMENTED |
| `QuantKernelAuthority` | 671 B | 2901 B | SOURCE_IMPLEMENTED |
| `LayerComputeAuthority` | 730 B | 3508 B | SOURCE_IMPLEMENTED |
| `AttentionComputeAuthority` | 1416 B | 7696 B | SOURCE_IMPLEMENTED |
| `RopeComputeAuthority` | 453 B | 2331 B | SOURCE_IMPLEMENTED |
| `RmsNormComputeAuthority` | 537 B | 3053 B | SOURCE_IMPLEMENTED |
| `FfnComputeAuthority` | 537 B | 2631 B | SOURCE_IMPLEMENTED |
| `MoeComputeAuthority` | 504 B | 2616 B | SOURCE_IMPLEMENTED |
| `SsmComputeAuthority` | 467 B | 2545 B | SOURCE_IMPLEMENTED |
| `LogitsComputeAuthority` | 559 B | 2941 B | SOURCE_IMPLEMENTED |

The five absent ones are not incidental. They are the **first three P0 items**
in the ledger's own execution order (`requestRoute`, `beginStage`,
`LinearW::execute`) plus `KernelDictionaryAuthority::registerKernel` and
`ForwardPassAuthority::beginForward`.

Cross-checking the ledger's advertised call surface against source:

```text
requestRoute   hits=0     executeLinear   hits=0
beginStage     hits=0     registerKernel  hits=0
beginForward   hits=0
```

**None of the five headline direct-call entry points exist anywhere in the
source tree.**

## 4. Finding

> RawrXD carries an authority-documentation surface substantially larger than
> the set of authorities with source closure, and the gap is not marginal: the
> P0 compute entry points are named in the ledger but have no implementation,
> no header, and no call site.

Three distinct failure modes, which should not be conflated:

```text
STALE_CLAIM        5 compute authorities named, zero files exist
DEAD_SOURCE        10 compute authorities have real bodies, zero compile,
                   zero callers
DOCUMENTATION_ONLY 30+ authority names exist only as text
```

Only the middle group is recoverable by wiring. The first group requires the
claim to be withdrawn or the code written. The third requires nothing to be
built at all.

## 5. Remediation rule

```text
NO AUTHORITY MAY BE MARKED PASS unless:
    source exists
  AND implementation is non-stub
  AND a target compiles it
  AND a production path reaches it
  AND a receipt is generated from that path
```

Anything short of that is downgraded to the strongest state in §0. In
particular, `SOURCE_IMPLEMENTED` must never be reported as `PASS`, and a
non-empty `.cpp` file must never be taken as evidence that anything runs.

## 6. Note on the streamer harness, for continuity

`deep2_streamer_cert` and `deep2_streamer_parity` were **44–47 byte stubs**
(`// STUB: src/deep2/...`), so those CMake targets could never build. They are
now real (`tools/deep2_streamer_cert.cpp`, `src/streamer/ModelInventory.cpp`,
both `EXCLUDE_FROM_ALL`).

Defects found and fixed while bringing them up:

```text
src/deep2/deep2_streamer_cert.cpp:224  fs::path vs std::string  -> compile error
tools/deep2_streamer_cert.cpp:223      undeclared `callbacks`   -> compile error
tools/deep2_streamer_cert.cpp:223      streamContiguous scored
                                       "no repeated consecutive ids", which makes
                                       an instrument that can only disagree with
                                       correct output. Now: callbacks == reported
                                       generated tokens.
src/streamer/ModelInventory.cpp:254    m.shards.clear() then *kv.second, where
                                       `seen` holds pointers INTO m.shards.
                                       Use-after-free.
```

And one finding that invalidated a whole census:

```text
encodeGPT2 (Tokenizer.cpp:545) returns {} when ANY symbol is missing from the
vocab and no unk id exists -- one unknown character discards the entire
encoding. A shared harness prompt of "Count:" therefore produced 0 tokens and
the first full run reported 182/182 MODEL_LOAD_FAILED.

That was ONE bug wearing 182 model-shaped coats. It is not evidence that 182
models are broken.

STREAMER STATUS = NOT YET RUNNABLE.
Outstanding: LogicalModel shard paths come back empty (path=, arch=UNKNOWN,
"no entry shard") for every model including single-file ones, so no artifact
can currently be attempted. Root cause not yet established.
```

## 7. Storage reclamation performed

```text
DELETED  F:\OllamaModels\DeepSeek-R1-Q4_K_M\.cache\huggingface\download
         169.84 GB, 56 files, 36 of them *.incomplete
         verified redundant first: DeepSeek-R1-Q4_K_M-COMPLETE holds all 11
         shards (376.65 GB) with zero truncated members

NOT FOUND  "1.57 GB incomplete Git LFS Kimi data"
           zero .git directories exist anywhere under F:\OllamaModels
           nothing was deleted; the target as described does not exist
```

## 8. Provenance

Measurements: `Get-ChildItem` / `Select-String` over `F:\~dev\rawrxd`,
`git log` / `git ls-files` for tracked-file status, `CMakeLists.txt` scanned for
both explicit `src/compute` references and `file(GLOB ...)` directives.