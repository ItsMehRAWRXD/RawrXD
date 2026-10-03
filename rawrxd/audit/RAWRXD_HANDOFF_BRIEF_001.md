# RAWRXD_HANDOFF_BRIEF_001

**Purpose:** take ownership of RawrXD/Deep2 from its current verified state and drive it
to production readiness. Do not restart solved investigations. Do not replace measured
facts with assumptions.

Every number below was produced by a tool in this repository or on this host. Claims that
were NOT verified are marked `RETRACTED` or `UNVERIFIED`, and exist here so the next owner
does not repeat them.

---

## 1. Measured state — safe to build on

### 1.1 Inference

```ini
MODEL                       DEcode_TOK/S   PREFILL_TOK/S
qwen2.5-coder:1.5b-base        256.89          330.3
llama3.2:3b                   177.17          973.6
gemma3:4b                     131.01          337.8
qwen3:8b                       88.75          129.0
llama3.1:8b                    88.11          257.0
granite3.3:8b                  79.26          569.5
Deep2 on llama3.2-3b-Q2_K        0.45           (prefillMs=12932.6)
```

Source: Ollama `/api/generate` `eval_count/eval_duration`, and the streamer cert receipt.
Deep2 is **394x slower than Ollama** on the same architecture, machine and a smaller
quantization. Treat as the headline deficit; it is one model, not a subsystem attribution.

### 1.2 Working end to end

```ini
llama3.2-3b-Q2_K.gguf
  MODEL_PASS   promptTokens=5   generated=8   callbacks=8
  prefillMs=12932.6   decodeMs=17732.4   cleanTeardown=1
```

Built as `deep2_streamer_cert_mla.exe` (hand-linked; see 3.1).

### 1.3 MLA — admission proven, execution not

```ini
MODEL_ADMITTED          = 1     tensors bound=1096, MLA layers 61/61
ARCH                    = deepseek2   layout=split   geometryValidated=1
KV_LORA_RANK=512  Q_LORA_RANK=1536  QK_NOPE=512  QK_ROPE=64  KEY_LEN=576  VALUE_LEN=512
FORWARD_REACHED        = 1     MLA_ELIGIBLE layersBound=61/61
TOKENS_FROM_KIMI       = 0     never
```

### 1.4 Hardware

```ini
VK_ENUMERATED_DEVICE_COUNT = 3   R9700 31.86GB / RX7800XT 15.98GB / AMD iGPU
PEER_HANDOFF_SUPPORTED    = 0   R9700 <-> RX7800XT, measured at init
PLAN_ACTIVE               = 0
STRICT_MODE               = 1   default true, Deep2Engine.h:1391
```

---

## 2. Retracted — do not repeat these

Each was asserted by me and withdrawn on evidence. They cost real time.

```ini
RETRACTED  "printf/failed-return-check caused the crash"
           actual: fflush returns 0/nonzero, printf returns a char count.
           THE ANSWER WAS ALREADY IN THE LOG. grep for GEMV_SINGLE.

RETRACTED  "the failing call was an IAT import"
           actual: section table places the operand in .text, not .rdata.

RETRACTED  "deep2_streamer_cert.cpp telemetry broke the dense model"
           actual: enableVulkan(true) did. It makes every GPU GEMV path ELIGIBLE while
                   nothing uploads weights, so fullView() declines, and strict mode
                   forbids the host lane. Removed; model streams again.

RETRACTED  "Wire::WireRecordDispatch has no definition, Wire.cpp absent"
           actual: InferenceWire.cpp:558 defines it. 25KB. COMMITTED at e7fb2efa0.
           I inferred a missing file from a namespace and never opened the file.

RETRACTED  "dual-row capability gate is the defect"
           actual: the gate IS a real defect and IS fixed, but it was a symptom of
                   the enableVulkan mistake above.

RETRACTED  "the primary driver of the 394x deficit is a missing CPU feature probe"
           actual: `QuantKernelRegistry.cpp:1989` selects AVX-512 Q4_K GEMV only
                   under `hasAVX512`, and `ProbeCPU()` was un-called in at least one
                   tool (`DecodaStream.cpp`, now fixed). This makes `ProbeCPU()` a
                   **high-priority hypothesis**, not a proven root cause. The 394x gap
                   (Deep2 0.45 tok/s vs Ollama 177.17 tok/s) is **measured**; its
                   attribution is **unproven** until stage-budget instrumentation
                   confirms or rejects the dispatch hypothesis.

UNVERIFIED "nested function defs / orphaned try at base"
           I measured them by pattern, never compiled the committed base.
           Withdrawn as an inherited-failure claim.
```

---

## 3. Build graph — the highest-leverage defect class

### 3.1 InferenceWire — completed prerequisite, needs clean-build preservation

```ini
InferenceWire.cpp wired into Deep2Engine targets = 26
DOUBLE_INSERTS                                  = 0
wt_cert3.exe LINK                               = PASS
```

This was previously a primary defect (`appears in 0`). It is now **wired**.
The next requirement is not "wire it"; it is:

```ini
prove the 26-target integration survives a clean configure/build
without touching contested CMake ownership
```

Evidence required:
```ini
CFG_EXIT=0
BUILD_EXIT=0
WireRecordDispatch_RESOLVES=1
NO_REGRESSION_TO_HAND_LINKED_ONLY_BINARIES=1
```

### 3.2 The same shape, repeatedly

| instance | evidence |
|---|---|
| `src/compute` | 16 files, 0 CMake refs, 0 production callers, advertised in AGENTS.md |
| `src/deep2/InferenceWire.cpp` | 25KB, committed, 0 CMake refs, called by 27 targets |
| `ResidencyTracker` + 4 siblings | **2 bytes each** (a newline), referenced by CMake at 606-610, 821-822 |

A committed `.cpp` that no target compiles passes every check a reader can make and is
absent from the only surface that matters. **Hunt by `git ls-files '*.cpp'` minus
CMake-referenced sources**, not by comparing docs to code.

### 3.3 Unenabled IDE sources — measured

```ini
src/win32app  .cpp 43 on disk, 39 referenced, 4 unenabled
  IdeChatAuthority.cpp              DOES NOT COMPILE: ../ReceiptAuthority.h missing
  IdeResponseCompletionAuthority.cpp DOES NOT COMPILE: self-include path wrong
  W8LifecycleAuthority.cpp          DOES NOT COMPILE: std::mutex without <mutex>
  test_string.cpp                   3-line stray: global std::string s, no purpose
src/win32app .h 13 on disk, 0 "referenced"  -- FALSE POSITIVE, all are #included by
                                    the 39 compiled TUs. Do NOT add to source lists.
src/win32ide  0 files
```

None of the 3 has ever been compiled. `test_string.cpp` is scratch and should be deleted
or moved, not shipped.

---

## 4. Worktrees and ownership — preserve

```
lane-1  F:\wt_ide1        rawrxd/s15-tps-panel       owns src/win32app/**
lane-2  F:\wt_compute1    rawrxd/compute-authority    owns src/compute/**
lane-3  F:\wt_agentic1    rawrxd/tool-sandbox         owns src/agentic/**
mine    F:\~dev            beacon-residency-001        owns src/deep2/**

BASE_HEAD     = e7fb2efa0cc2d2fbfcb5e8d2585cd56452285253
BASE_TREE_SHA = 6bc140060dfa7fc76b030fae27cee165ccf5febb
```

`RAW_LANE_CONTRACT.md` exists in each lane with ALLOWED/FORBIDDEN sets, the
`KNOWN_BASE_DEFECT` list, and a correction notice. Read it before editing there.

**`CMakeLists.txt` is contested.** Another session has 215 insertions / 36 deletions
uncommitted in it, with no lease file. It is FORBIDDEN to all four lanes. Do not commit it
while dirty — that is how `e7fb2efa0` came to contain 589 files, 19 of them explicitly
attributed to other sessions.

---

## 4b. BINDING HANDOFF — RAWRXD_SOURCE_GRAPH_AUTHORITY_001

The ledger, not CMake comments or regex counts, is the source-materialization
authority. This gate **measures the gap**. It does not close it.

**HARD RULE — the gate must never be satisfiable by creating files.**

```text
ABSENT_DECLARED_SOURCE        = defect
COMMENTED_DECLARED_SOURCE    = defect
EMPTY/PLACEHOLDER_IMPL       = NOT a functional PASS
```

Creating an empty `.cpp` to move `ABSENT` to 0 converts a real absence into a
synthetic presence. That is `return true` at 354x scale. `ACTIVE_MISSING` is the
implementation queue; it is consumed by WRITING IMPLEMENTATIONS, never by
creating translation units whose only content is their own existence.

### Fingerprints

```ini
GIT_HEAD                      = e7fb2efa0cc2d2fbfcb5e8d2585cd56452285253
GIT_STATUS_HASH               = <measured>
CMAKELISTS_SHA256            = <measured>
SOURCE_TREE_MANIFEST_SHA256   = <measured>

RESOLVED_SOURCE_SET_SHA256    = <measured>   canonical: repo-relative, sorted, deduped
GENERATED_INPUT_SET_SHA256   = <measured>   configure outputs, repo-relative
COMPILE_DB_PRESENT            = 0|1          EXISTENCE ONLY -- see correction
COMPILE_DB_MISMATCHES_R1_R2   = <measured>   EXPECT NON-ZERO; that is its purpose
```

**CORRECTION to the proposed gate: do NOT require
`COMPILE_DB_INPUT_SET_SHA256` to be byte-identical across two configure runs.**

CMake's compiler-dependency file is designed to DIFFER — that is how stale-object
detection works. It embeds absolute paths, timestamps and generator identity.
Requiring byte equality will fail on unchanged source, and the failure will be
debugged as a build problem when it is a gate-specification problem. Assert
existence; record the mismatch count as a measurement.

### Gate

```ini
=== RAWRXD_SOURCE_GRAPH_AUTHORITY_001 ===
PARSER_DETERMINISTIC          = 0|1
TREE_UNCHANGED_BETWEEN_RUNS   = 0|1
RESOLVED_SET_IDENTICAL        = 0|1
RECONFIGURE_REPEATABILITY     = 0|1
GENERATED_GRAPH_CROSSCHECK    = 0|1
COMPILE_DB_CROSSCHECK         = PRESENCE ONLY
UNEXPLAINED_COUNT_DIFFERENCES = 0|1
UNKNOWN                      = <measured>   must be 0 to PASS

ACTIVE_MISSING               = <measured>   <- the queue
COMMENTED_REFS               = <measured>
FILTER_DROPPED                = <measured>

RUN1_LEDGER_SHA256            = <measured>
RUN2_LEDGER_SHA256            = <measured>

VERDICT = PASS only if the six determinism checks pass AND UNKNOWN=0.
         PASS does NOT require ACTIVE_MISSING=0.
         PASS certifies that the architecture is FULLY VISIBLE and REPRODUCIBLE.
         It explicitly does NOT certify that any of it exists or works.
```

That distinction is the whole gate. A gate that requires `ACTIVE_MISSING=0`
cannot tell implementation from file creation. A gate that requires
determinism and full visibility can.

### Configure receipt — install this, it is pure measurement

```cmake
# --- RAWRXD BUILD GRAPH DIAGNOSTIC RECEIPT (RAWRXD_GRAPH_MEASURE_001) ---
# Reports the gap. Emits no VERDICT and closes nothing.
message(STATUS "RAWRXD_GRAPH_SOURCES_REFERENCED=${RAWRXD_NUM_REFERENCED}")
message(STATUS "RAWRXD_GRAPH_SOURCES_PRESENT=${RAWRXD_NUM_PRESENT}")
message(STATUS "RAWRXD_GRAPH_SOURCES_ABSENT=${RAWRXD_NUM_ABSENT}")
message(STATUS "RAWRXD_GRAPH_ABSENT_CPP=${RAWRXD_NUM_ABSENT_CPP}")
message(STATUS "RAWRXD_GRAPH_COMMENTED_OUT_REFS=${RAWRXD_NUM_COMMENTED}")
message(STATUS "RAWRXD_GRAPH_ABSENT_BY_AREA=${RAWRXD_ABSENT_AREA_STRING}")
message(STATUS "RAWRXD_GRAPH_ACTIVE_MISSING=${RAWRXD_NUM_ACTIVE_MISSING}")
message(STATUS "RAWRXD_GRAPH_COMMENTED_MISSING=${RAWRXD_NUM_COMMENTED_MISSING}")
message(STATUS "RAWRXD_GRAPH_COMMENTED_PRESENT=${RAWRXD_NUM_COMMENTED_PRESENT}")
```

The `325` commented-out references are not noise to be cleaned. Each one is a
person having already written down that the architecture is incomplete. Un-commenting
them and creating empty files deletes the record of the gap and replaces it with 325
files claiming completeness.

---

## 5. Telemetry — live, and it is the thing that pays for itself

```ini
PRODUCER  src/deep2/deep2_streamer_cert.cpp   schema RAWRXD_STREAMER_TELEMETRY_V1
SINK      %LOCALAPPDATA%\RawrXD\streamer_telemetry.jsonl   (override RAWRXD_STREAMER_TELEMETRY)
CONSUMER  tools/streamer_status.cpp            compiles clean
```

Append + `fflush` + `_commit` per record, so a run killed by fast-fail keeps completed
records. Run header carries the SHA-256 of the running image plus a
`sha256_selftest=PASS`, so no result can be read without knowing which binary produced it.

**Known defects, both in the producer (`src/deep2/**`, lane-deep2 owns them):**

```ini
decode_tps conflates prefill with decode
  observed  stream reports tps=0.45, sink record reports 0.2573, same run
--child mode emits no sink record
  telemetryModel() runs only in the parent census loop
```

**This telemetry immediately caught a regression** that console logs alone had hidden:
a previously passing model failed at prefill token 0. Do not remove it in favour of
`printf`.

---

## 6. Recommended critical path

```ini
1  Preserve/prove the completed InferenceWire integration.
      - clean configure/build
      - WireRecordDispatch resolves
      - no regression to hand-linked-only binaries

2  Close the known IDE source defects.
      - ReceiptAuthority.h path defects
      - missing <mutex>
      - IdeResponseCompletionAuthority include
      - classify/remove test_string.cpp
      - do NOT modify contested CMakeLists.txt

3  Establish RAWRXD_SOURCE_GRAPH_AUTHORITY_001.
      - canonical active-source ledger
      - generated graph cross-check
      - compile_commands cross-check
      - UNKNOWN=0

4  Get the current Win32 IDE:
      COMPILE=PASS
      LINK=PASS
      IDE_LAUNCH=PASS

5  Instrument absolute Deep2 decode cost.
      TOKEN_LOOP  KV_CACHE  Q_PROJECTION  K_PROJECTION  V_PROJECTION
      ROPE  ATTENTION  FFN  SAMPLER

6  Test the ProbeCPU / AVX-512 hypothesis.
      Do not declare it causal until the dispatch and TPS measurements prove it.

7  Implement actual GPU weight residency/staging.
      enableVulkan(true) alone is explicitly insufficient.

8  Wire src/compute or downgrade claims about it.

9  Repair telemetry semantics:
      decode-only TPS
      child-process records
      image hash + raw exit code retention

10 Re-attempt MLA/Kimi only after dense inference and residency are authoritative.

11 Consolidated IDE + inference + agentic E2E certification.
```

---

## 7. Claim taxonomy (preserve throughout)

```ini
MEASURED    = directly observed
HYPOTHESIS  = plausible next investigation
PASS        = exercised by the relevant runtime/build path
RETRACTED   = disproven and must not be reintroduced
```

Mixing these categories is the failure mode that produced the stale claims above.
Every field in a handoff must carry one of these four labels.

## 8. Non-negotiables

```ini
no stubs                        no simulated success
no fictional PASS receipts      no "remaining code omitted"
no source-existence-as-reachability
no comment-as-implementation    no compile-as-runtime-proof
no shell-normalized exit codes  use the raw 32-bit status
separate MEASURED / HYPOTHESIS / RETRACTED in every receipt
```

A finding without file:line evidence is a hypothesis. A claim without an image hash is
an anecdote. Both have been produced repeatedly in this project and both were wrong.
