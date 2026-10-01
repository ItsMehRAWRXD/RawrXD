# RAWRXD_RAWR_CLI_BUILD_GRAPH_001

Batch: `rawr` CLI front door — build graph, `modelname` behaviour, measured display fields.
Date: 2026-09-30 / 2026-10-01
Scope of edits: `rawrxd/src/deep2/rawrxd_run_modelname_001.cpp`, plus `src/deep2/Sampler.cpp`,
`certs/rawrxd_sampler_combined_oob_001.cpp` and `CMakeLists.txt` under lease-owner authorization.
Status: CLOSED — see §8 and §9.

---

## 1. Batch header

```
BRANCH=model-correctness
HEAD=a078e3b87be6b22ed1fa6fce6a20bfdd980e4441
HEAD_SUBJECT=RECONCILE_MIGRATION_BATCH_1_001: legacy W8 mirror marked NON_AUTHORITATIVE
WORKTREE_DIRTY_ENTRIES_AT_START=135
LEASE_FILE_FOUND=0            (no *lease* file present in rawrxd\ at batch start)
BUILD_DIR=F:\~dev\rawrxd\build
GENERATOR=Visual Studio 17 2022
CONFIG=Release
```

---

## 2. The opening classification was wrong, and the build graph is not the blocker

The classification this batch started from asserted:

```
RAWR_CLI_BUILD=FAIL
RAWR_EXE_PRESENT=0
RAWRXD_RUN_MODELNAME_001_CPP_IN_TARGET=0
ROOT_CAUSE=BUILD_GRAPH_OMISSION
```

Every one of those is refuted by direct evidence.

| Claim | Measured | Evidence |
|---|---|---|
| `rawrxd_run_modelname_001.cpp` absent from the `rawr` target | `=1` (present) | `F:\~dev\rawrxd\build\rawr.vcxproj` lists 21 `<ClCompile>` entries; `src\deep2\rawrxd_run_modelname_001.cpp` is the 2nd |
| `rawr` target does not build | builds | `rawr.vcxproj -> F:\~dev\rawrxd\build\bin\Release\rawr.exe`, `COMPILE_ERRORS=0`, `LINK_ERRORS=0` |
| `rawr.exe` absent | present | `build\bin\Release\rawr.exe`, plus `build_clean_n1` and `build_w1` copies |

`CMakeLists.txt:9977-9998` is the canonical `add_executable(rawr ...)`, and it already listed
`src/deep2/rawrxd_run_modelname_001.cpp` — in `HEAD` as well as in the worktree. That was confirmed
directly rather than inferred:

```
git show HEAD:rawrxd/CMakeLists.txt | Select-String 'add_executable\(rawr\b' -Context 0,25
  -> add_executable(rawr
       src/deep2/rawr_run.cpp
       src/deep2/rawrxd_run_modelname_001.cpp
       ...
```

### The `src/cli` fragment is a real dead branch, and it is not what breaks `rawr`

`cmake/RawrAgenticCli.fragment.cmake:89` guards on
`if(EXISTS "${CMAKE_SOURCE_DIR}/src/cli/rawr_main.cpp")`. That file does not exist
(`src/cli/` exists; `src/cli/rawr_main.cpp` does not). So the fragment prints
`[RAWRXD_BUILD_SOURCE_INTEGRITY_001] Skipping agentic rawr CLI: missing src/cli/rawr_main.cpp ...`
and its `target_sources(rawr PRIVATE ${RAWR_AGENTIC_SOURCES})` at line 97 never runs. The
thin front door is what actually builds — and it is a complete target on its own. Inventing the 85
missing `src/cli` sources to satisfy the fragment would have been the wrong repair; nothing was
invented.

### `_rawrxd_run_modelname_001_main.cpp` cannot introduce a second `main()`

```
rg "_rawrxd_run_modelname_001_main" CMakeLists.txt cmake/   -> no matches (exit 1)
```

It is referenced by no target in the build system. Of the 21 sources that do land in `rawr`,
exactly one defines `int main(`:

```
rawr_run.cpp:1
```

### Symbol contract

`rawr_run.cpp` includes `rawrxd_run_modelname_001.h` and calls two functions:
`rawrxd_run_modelname_001(...)` at `rawr_run.cpp:106` and `rawrxd_list_models_001()` at
`rawr_run.cpp:127`. Both are declared in `rawrxd_run_modelname_001.h` and defined in the linked TU.
`rawr_run.cpp` also provides its own `int main()` at line 111. Contract satisfied at link time.

---

## 3. The real defect, reproduced and then diagnosed

`rawr.exe run modelname "blah"` produced:

```
EXIT_CODE            = -1073740791   (0xC0000409)
ELAPSED_SEC          = 10.143
LAST OUTPUT          = [rawr run] MODEL_RESOLUTION: resolving 'modelname'
```

Note that `modelname` is not a subcommand. `rawr_run_main` takes `<model> <prompt...>`, so the
argument pair is model = `modelname`, prompt = `blah`. That is how the resolver is reached.

### 3a. The 0xC0000409 is an `abort()`, not a memory-safety fault

Windows Application log, `F:\~dev\rawrxd\build\bin\Release\rawr.exe`:

```
Event ID 1000  Application Error
  Exception code : 0xc0000409
  Faulting module: rawr.exe  (time stamp 0x6abda8db)
  Fault offset   : 0x00000000000e9b71

Event ID 1001  Windows Error Reporting
  Event Name    : BEX64
  P8            : c0000409
  P9            : 0000000000000007
```

`BEX64` subtype `7` is `FAST_FAIL_FATAL_APP_EXIT`, which is what MSVC's `abort()` raises. So the
process did not corrupt memory — it called `abort()`. The usual cause is an exception escaping
`main` into `std::terminate`. The dump names neither the stage nor the exception, so the cause was
measured directly (below) rather than guessed.

### 3b. Measured cause

`RAWRXD_RAWR_CLI_RESOLVE_TRACE_001` was added: monotonic stderr checkpoints through resolution,
plus a `std::set_terminate` handler that names the in-flight exception. With the trace on, the
run ends:

```
[resolve] UNCAUGHT_EXCEPTION=YES
[resolve] EXCEPTION=class std::system_error
[resolve] WHAT=No mapping for the Unicode character exists in the target multi-byte code page.
```

Root cause, measured:

- `resolveModelPath` walks directories with `std::recursive_directory_iterator` and **no depth or
  breadth bound**.
- It walks `F:\~dev` (116,795 entries) then `G:\~dev`, where it entered a directory name with no
  representation in the active ANSI code page. `<filesystem>` raised `std::system_error`.
- Nothing caught it. It left the resolver, left `rawrxd_run_modelname_001`, left `main`, and killed
  the process through `std::terminate -> abort()`.

Trace tail before the fault (verbatim, `RAWRXD_RESOLVE_TRACE=1`):

```
[resolve t=   0.006s] resolve_model ollama_store_stage_enter
[resolve t=   0.008s] ollama_store conventional_hit path=F:\OllamaModels
[resolve t=   0.010s] resolve_model ollama_store_stage_done hit=0
[resolve t=   0.012s] resolve_model search_dir_enter path=F:\models
[resolve t=   0.015s] resolve_model search_dir path=F:\~dev visited=50000
[resolve t=   1.525s] resolve_model search_dir path=G:\~dev visited=150000
[resolve t=   5.183s] resolve_model search_dir path=G:\~dev visited=950000
[resolve] UNCAUGHT_EXCEPTION=YES
```

Two measured defects, not one:

1. **Uncontained filesystem exception** — a wrong model name killed the process instead of being
   reported as not found.
2. **Unbounded search, and it was ordered ahead of the model store.** `F:\OllamaModels` is the store
   that had just been discovered, and it sat *after* `G:\~dev` in the search order. So a model that
   was present all along could lose to a source tree that was not, after 5+ seconds of walking.

---

## 4. Fixes applied (`rawrxd_run_modelname_001.cpp` only)

- `RAWRXD_RAWR_CLI_RESOLVE_CONTAINMENT_001` — the resolver is sealed. `resolveModelPathImpl` is
  wrapped by `resolveModelPath`, which catches `filesystem_error`, `std::exception`, and `...`, names
  the failure, and returns empty. A failed resolution is now a reportable outcome.
- `RAWRXD_RAWR_CLI_RESOLVE_BUDGET_001` — per-directory visit budget of 400,000 entries. Exhaustion
  is reported as `MODEL_RESOLUTION=INCONCLUSIVE`, never as "searched everywhere, found nothing".
- The structurally-discovered Ollama store root (and its `blobs` dir) is now searched **before** the
  broad directory walks, and is computed once (`ollamaModelsRootCached`) instead of twice.
- Remaining throwing `std::filesystem` overloads in the resolution path (`fs::exists(p)`,
  `fs::current_path()`) were converted to `error_code` overloads.
- `RAWRXD_RAWR_CLI_RESOLVE_TRACE_001` — checkpoints + terminate handler, opt-in via
  `RAWRXD_RESOLVE_TRACE=1`. Normal runs are unchanged on stderr.

A defect in the first draft of the fix was found by the rerun and corrected: the `INCONCLUSIVE`
report sat after the `try` block, so on the non-throwing path — the common one — it was
unreachable. It now runs on both paths, guarded by `resolved.empty()`.

---

## 5. Verification (measured, after rebuild)

Rebuild of the `rawr` target: `rawrxd_run_modelname_001.cpp` only, `COMPILE_ERRORS=0`,
`LINK_ERRORS=0`, `rawr.vcxproj -> F:\~dev\rawrxd\build\bin\Release\rawr.exe`.

### Case A — the requested command, `rawr run modelname "blah"`

```
EXIT_CODE=1
WALL_MS=4075.6
STDOUT=(empty)
STDERR=
  [rawr run] MODEL_RESOLUTION: resolving 'modelname'
  [rawr run] MODEL_RESOLUTION=INCONCLUSIVE  per-directory search budget of 400000 entries was
             reached; deeper locations were not examined. Set RAWRXD_MODEL_DIR or pass an
             absolute .gguf path.
  [rawr run] MODEL_RESOLUTION=FAIL  could not locate 'modelname'
    Set RAWRXD_MODEL_DIR or pass an absolute .gguf path.
```

### Case B — regression, a real model still resolves, loads and generates

`rawr run --tokens 1 qwen2.5-coder:1.5b-base hi`

```
MODEL_RESOLUTION=PASS
MODEL=F:\OllamaModels\blobs\sha256-6a77366395772462c84f0c4d226ac404674327cbe78c01e4391cc7e0c698851e
PROMPT_TOKENS=1
GENERATED_TOKENS=1
WALL_MS=2664.4
TPS=0.375
PEAK_TPS=0.375
COMPLETED=YES
```

Resolution, load and decode all still work after the containment and reordering.

---

## 6. Acceptance target — measured

`blah` is not a model. There is no product definition of a silent fallback, so the honest branch
applies.

```
REQUESTED_MODELNAME=modelname          # 'modelname' is the model argument; 'blah' is the prompt
MODEL_FOUND=0
FALLBACK_USED=0
ERROR_EXPLICIT=1                       # MODEL_RESOLUTION=FAIL on stderr
EXIT_CODE_NE_0=1                       # EXIT_CODE=1
PROCESS_ABORTED=0                      # was 1 (0xC0000409 / BEX64 subtype 7)
TRUNCATED_SEARCH_DISCLOSED=1           # MODEL_RESOLUTION=INCONCLUSIVE
DISPLAY_MODEL_MATCHES_RESOLUTION=1     # nothing is displayed, because nothing resolved
HARDCODED_DISPLAY_FIELDS=0
```

---

## 7. The `glm-5.2:cloud` / `39s` / `6:30 AM` question

These three strings do not come from `rawr`.

```
rg -e 'glm-5\.2' -e '6:30' -e '\b39s\b'   (whole repo, excluding build trees)
  rawrxd\_ollama_tags.json:1  "name":"glm-5.2:cloud", ... "modified_at":"2026-08-16T00:40:55..."
```

`glm-5.2:cloud` appears **once**, inside `_ollama_tags.json` — a captured `ollama list` payload
listing genuine Ollama tags. It is data, not a display field, and it is not reachable from the
`rawr` target. `6:30 AM` and `39s` appear nowhere outside recovery manifests and SHA-256 hex
coincidences. None of the three is emitted by any `rawr` source file.

The `rawr` receipt fields were checked individually against their printf arguments:
`MODEL`=`ggufPath`, `WALL_MS`=`genMs`, `TPS`/`PEAK_TPS`=derived from `tokenCount`/`genMs`,
`COMPLETED`=`result.completed`. Every one is measured. `HARDCODED_DISPLAY_FIELDS=0` stands on its
own evidence; there was nothing to fix.

---

## 8. Open blocker — RESOLVED under lease-owner authorization

```
INFERENCEENGINE_BUILD=PASS          (was FAIL)
FULL_TARGET_REBUILD_VERIFIED=1      (was 0)
```

`src/deep2/Sampler.cpp` had been rewritten by another writer at 20:32:43 and again at 20:37:55.
The 20:37:55 revision did compile — it had already replaced the raw `uint64_t (*)()` RNG
parameter with a `std::function<uint64_t()>` and had replaced the unrepresentable divisor
`0x10000000000000000ULL` with `1.0 / 18446744073709551616.0`. The compile errors recorded earlier
in this receipt are therefore stale, and are superseded by the measurements below.

### 8a. A memory-safety defect the compiling revision still contained

`CombinedSampler::sample` narrowed `probs` to `topK_` entries in the top-k step while `idx` kept
original vocabulary ids, then used those ids as subscripts:

```cpp
std::sort(idx.begin(), idx.end(), [&](int a, int b){ return probs[a] > probs[b]; });
                                                          ^^^^^^   ^^^^^
   a, b are original vocab ids (up to n_vocab-1)     probs.size() == topK_
```

With `n_vocab = 151936` and `topK = 40` that is a read up to ~600 KB past the end of the
allocation. The same narrow-then-return path also returned a *position* where a token id belonged
in the pure-temperature fallback.

This is unreachable from `rawr run`, which pins `opts.temperature = 0.0f` and `opts.topK = 1`
(`rawr_run.cpp:439-441`) and therefore never enters `CombinedSampler` at all. A green CLI run
cannot have caught it.

### 8b. Fix

`src/deep2/Sampler.cpp` only:

- `probs` is kept positionally aligned with `idx` throughout; the top-k step shortens both
  together via `probs.swap(kp)`.
- The top-p nucleus step now sorts an `order` vector of **positions** and returns
  `idx[order[pick]]`, so a token id is never used as a subscript.
- The minP and pure-temperature paths return `idx[...]` rather than a position.
- `categoricalDraw` is templated on the RNG callable instead of taking `const std::function&`,
  which removes the per-draw heap allocation the `std::function` workaround introduced, and the
  no-op `& 0xFFFFFFFFFFFFFFFFULL` mask on a `uint64_t` was dropped.
- The three `double`-to-`float` implicit narrowings in the softmax are now explicit casts, so the
  new `/W4` target builds without `C4244`.

### 8c. Gate: `RAWRXD_SAMPLER_COMBINED_OOB_001`

```
certs/rawrxd_sampler_combined_oob_001.cpp          (new)
CMakeLists.txt:10037                               (new standalone target)
```

It compiles `Sampler.cpp` directly and deliberately does **not** link `InferenceEngine`, so it
stays buildable while the engine is mid-change. It places the top-k tokens at the very end of a
151,936-entry vocabulary so a wrong subscript lands far outside the allocation rather than on
memory that happens to look like a probability, and it asserts that every returned token id is in
range *and* in the retained set.

### 8d. The gate was proven able to fail

A gate that cannot fail is the exact failure mode this project has already been retracted for
once, so the cert was run against a reconstruction of the pre-fix `CombinedSampler`:

```
NEGATIVE CONTROL, WITH AddressSanitizer
  ==18436==ERROR: AddressSanitizer: container-overflow
  READ of size 4 at 0x027201635dcc thread T0
    #0 rawrxd::sampling::CombinedSampler::sample'::<lambda_2>::operator()
       Sampler_prefix_control.cpp:193
    #6 rawrxd::sampling::CombinedSampler::sample(float const *, int)
       Sampler_prefix_control.cpp:193
  0x027201635dcc is located 607692 bytes inside of 607783-byte region
  CONTROL_EXIT=1

NEGATIVE CONTROL, WITHOUT AddressSanitizer  (matches how the in-repo target is built)
  FAIL CombinedSampler [topK+fallback] token id 0 is outside the retained set
  CHECKS=1900
  IN_RANGE_VIOLATIONS=1000
  VERDICT=FAIL
  CONTROL_NOASAN_EXIT=1

IN-REPO CERT against the fixed Sampler.cpp
  CHECKS=1900
  IN_RANGE_VIOLATIONS=0
  OOB_SUBSCRIPT_READS=0
  VERDICT=PASS
  CERT_EXIT=0
```

ASan pinned the fault to line 193, which is exactly the sort comparator identified above. The
non-ASan control confirms the in-repo target is itself a real gate and not a rubber stamp.

The ASan builds were scratch harnesses under
`C:\Users\Garrett\AppData\Local\Temp\kilo\sampler_verify\`. No repository target builds from
them, and nothing from that directory is referenced by the build system.

---

## 8e. Full rebuild with project references

```
cmake --build build --config Release --target rawr
  Sampler.cpp
  InferenceEngine.vcxproj -> F:\~dev\rawrxd\build\Release\InferenceEngine.lib
  rawr.vcxproj           -> F:\~dev\rawrxd\build\bin\Release\rawr.exe
COMPILE_ERRORS=0
LINK_ERRORS=0
INFERENCEENGINE_LIB_LINKED=CURRENT_SOURCE_TREE   (the earlier STALE_PRE_SAMPLER_REWRITE qualifier
                                                  no longer applies)
```

Final CLI measurements on these binaries:

```
CASE A   rawr run modelname "blah"
  EXIT_CODE=1   WALL_MS=3072.6   STDOUT_BYTES=0
  MODEL_RESOLUTION: resolving 'modelname'
  MODEL_RESOLUTION=INCONCLUSIVE  per-directory search budget of 400000 entries was reached
  MODEL_RESOLUTION=FAIL  could not locate 'modelname'

CASE B   rawr run --tokens 4 qwen2.5-coder:1.5b-base "Say OK"
  EXIT_CODE=0   WALL_MS=9103.9
  MODEL_RESOLUTION=PASS  path=F:\OllamaModels\blobs\sha256-6a773663...851e
  MODEL_LOAD=PASS  719 ms
  GENERATED_TOKENS=4   WALL_MS=8044.5   COMPLETED=YES
  stdout=", I'm not"
```

Case B exercises the greedy path only. The stochastic path is what the sampler cert covers, and
it is covered separately and directly.

---

## 9. Ledger entry

```
RAWRXD_RAWR_CLI_BUILD_GRAPH_001=CLOSED
BUILD_GRAPH_OMISSION=REFUTED
RAWR_RUN_CPP_IN_TARGET=1
RAWRXD_RUN_MODELNAME_001_CPP_IN_TARGET=1
RAWR_EXE_EXISTS=1
RAWR_TARGET_COMPILE_ERRORS=0
RAWR_TARGET_LINK_ERRORS=0
SECOND_MAIN_IN_RAWR_TARGET=0
RESOLUTION_ABORT_0xC0000409=FIXED_MEASURED
RESOLUTION_EXCEPTION_CONTAINED=1
RESOLUTION_SEARCH_BOUNDED=1
RESOLUTION_SEARCH_ORDER_FIXED=1
MODELNAME_OUTCOME=EXPLICIT_NOT_FOUND
MODELNAME_EXIT_CODE=1
REGRESSION_REAL_MODEL_RESOLVES_LOADS_GENERATES=PASS
HARDCODED_DISPLAY_FIELDS=0

INFERENCEENGINE_BUILD=PASS
FULL_TARGET_REBUILD_VERIFIED=1
INFERENCEENGINE_LIB_LINKED=CURRENT_SOURCE_TREE

SAMPLER_COMBINED_OOB_FIXED=1
SAMPLER_OOB_GATE=RAWRXD_SAMPLER_COMBINED_OOB_001
SAMPLER_OOB_GATE_NEGATIVE_CONTROL=FAIL_AS_EXPECTED
SAMPLER_OOB_GATE_EXIT=0
SAMPLER_OOB_GATE_CHECKS=1900
SAMPLER_OOB_GATE_IN_RANGE_VIOLATIONS=0
SAMPLER_OOB_GATE_W4_CLEAN=1

VERDICT=PASS
```

Every field above is measured from a command in this receipt. No field is a literal written to
satisfy a gate: the two `VERDICT` strings are printed by code that counts failing checks, and the
sampler cert was demonstrated to print `VERDICT=FAIL` with exit 1 against the pre-fix
implementation.

Scope note: this batch closed the CLI build graph and the resolver defect, and, under lease-owner
authorization, the `InferenceEngine` blocker. It did not touch the IDE startup hang, which remains
undiagnosed with no `dumpbin` evidence and no instrumented startup checkpoints.