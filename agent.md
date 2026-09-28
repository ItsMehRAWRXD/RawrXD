# RawrXD Agent Engineering Status

## Source / Build Compatibility Table
ID|Area|Current Status|Evidence|Missing Proof|Required Gate|Priority
---|---|---|---|---|---|---
SRC-001|Placeholder source integrity|⚠️ OPEN|Large number of `src/**/*.cpp` files were previously identified as one-line `// STUB:` placeholders|Confirm which placeholders are still reachable by production targets and remove/restore required implementations|`RAWRXD_SOURCE_INTEGRITY_001`|P0
CMAKE-001|Missing-source filtering|🟡 PARTIAL|`rawrxd_filter_missing_sources()` exists in `CMakeLists.txt`|Existing placeholder files are not necessarily rejected because they technically exist|`RAWRXD_CMAKE_SOURCE_TRUTH_001`|P0
CMAKE-002|Legacy certification isolation|🟡 PARTIAL|`RAWRXD_BUILD_LEGACY_CERTS` option exists and defaults OFF|Clean configure/build must prove legacy targets no longer contaminate production build|`RAWRXD_CMAKE_CONFIGURE_001`|P1
ENTRY-001|CEO main.cpp compatibility|🔴 UNPROVEN|`CMakeLists.txt` currently substitutes `src/ceo/main.cpp` for the previous `src/main.cpp`|No evidence yet that `src/ceo/main.cpp` is API-, ABI-, lifecycle-, or behavior-compatible with the RawrXD target|`RAWRXD_CEO_MAIN_COMPAT_001`|P0
ENTRY-002|Process entry point|🔴 OPENCEO source exists|Determine expected `main`, `wmain`, `WinMain`, or `wWinMain` contract and verify CEO implementation matches target subsystem|`RAWRXD_CEO_ENTRYPOINT_001`|P0
ENTRY-003|Old-main responsibility parity|🔴 OPEN|Historical `src/main.cpp` can be compared if substantive version exists in Git history|Recover old responsibilities and classify each as `PRESERVED`, `MOVED`, `OBSOLETE`, or `MISSING`|`RAWRXD_CEO_RESPONSIBILITY_PARITY_001`|P0
ENTRY-004|CEO compile compatibility|🔴 OPEN|None yet|Prove all CEO includes, declarations, types, and APIs compile against current RawrXD source|`RAWRXD_CEO_COMPILE_001`|P0
ENTRY-005|CEO link compatibility|🔴 OPEN|None yet|Prove all symbols used by CEO have real implementations and no unresolved externals|`RAWRXD_CEO_LINK_001`|P0
ENTRY-006|CEO launch compatibility|🔴 OPEN|None yet|Build executable and prove it starts without early crash or entry-point mismatch|`RAWRXD_CEO_LAUNCH_001`|P0
ENTRY-007|CEO subsystem initialization|🔴 OPEN|None yet|Verify configuration, runtime, Deep2, agent authority, IDE/server, and required services initialize|`RAWRXD_CEO_BOOT_001`|P0
ENTRY-008|CEO → Deep2 authority|🔴 OPEN|None yet|Prove CEO reaches the native Deep2 inference path rather than a stub/test-only/legacy backend|`RAWRXD_CEO_DEEP2_001`|P0
ENTRY-009|CEO real inference|🔴 OPEN|None yet|Model load → tokenize → forward → finite logits → sampled/generated token|`RAWRXD_CEO_INFERENCE_001`|P0
ENTRY-010|CEO → agent authority|🔴 OPENAgent architecture exists elsewhere|Prove CEO initializes/reaches the authoritative PLAN → DETECT/PROPOSE → AUTHORIZE/APPLY/RECORD chain|`RAWRXD_CEO_AGENT_AUTHORITY_001`|P1
ENTRY-011|CEO → IDE/chat E2E|🔴 OPEN|Chat UI exists|Prove Chat Send → request dispatch → Deep2 → token stream → chat render|`RAWRXD_CEO_CHAT_E2E_001`|P0
ENTRY-012|CEO shutdown/lifetime|🔴 OPEN|None yet|Prove cancellation, worker join, Deep2 teardown, GPU teardown, server stop, and clean process exit|`RAWRXD_CEO_SHUTDOWN_001`|P1
LOAD-001|Parallel GGUF loader substitution|🔴 UNPROVEN|`gguf_tensor_parallel_loader.cpp` substituted in CMake|No evidence it is API/behavior compatible with the previous tensor loader for all RawrXD callers|`RAWRXD_PARALLEL_LOADER_COMPAT_001`|P0
BUILD-001|Clean production configure|🔴 OPEN|CMake edits inspected|Fresh-cache CMake configure has not been certified|`RAWRXD_BUILD_CONFIGURE_001`|P0
BUILD-002|Clean production compile/link|🔴 OPEN|None yet|Production target must compile and link from a clean build tree|`RAWRXD_BUILD_RELEASE_001`|P0
BUILD-003|Stub-free production build|🔴 OPEN|Stub inventory known to be a concern|Prove required production paths do not resolve through placeholder/no-op/fake-success implementations|`RAWRXD_STUB_FREE_BUILD_001`|P0

---

# CEO `main.cpp` Compatibility — Required Completion Batches

## Batch CEO-00 — Freeze Contract
**Objective:** Define exactly what compatibility means before modifying code.

Required receipt:

```
GATE=RAWRXD_CEO_MAIN_COMPAT_001

ENTRYPOINT_REQUIRED=UNKNOWN
ENTRYPOINT_ACTUAL=UNKNOWN

OLD_MAIN_RECOVERED=0
RESPONSIBILITY_MATRIX_COMPLETE=0

COMPILE=UNKNOWN
LINK=UNKNOWN
LAUNCH=UNKNOWN
DEEP2=UNKNOWN
AGENT_AUTHORITY=UNKNOWN
CHAT_E2E=UNKNOWN
SHUTDOWN=UNKNOWN

VERDICT=HOLD
```

---

## Batch CEO-01 — Recover Previous Entry-Point Responsibilities
Compare:

```
historical src/main.cpp
        vs
current src/ceo/main.cpp
```
Every previous responsibility must be classified:

Responsibility|Old Main|CEO Main|Classification
---|---|---|---
Process entry point|TBD|TBD|TBD
CLI/argument parsing|TBD|TBD|TBD
Environment initialization|TBD|TBD|TBD
Logging|TBD|TBD|TBD
Configuration|TBD|TBD|TBD
Runtime creation|TBD|TBD|TBD
Deep2 initialization|TBD|TBD|TBD
Model loading|TBD|TBD|TBD
Agent authority|TBD|TBD|TBD
Tool authority|TBD|TBD|TBD
IDE startup|TBD|TBD|TBD
Server startup|TBD|TBD|TBD
Error propagation|TBD|TBD|TBD
Shutdown/cleanup|TBD|TBD|TBD

Allowed classifications:

```
PRESERVED
MOVED
OBSOLETE
MISSING
```
No `MISSING` responsibility may remain without an explicit resolution.

---

## Batch CEO-02 — Entry-Point Contract
Determine the actual CMake executable subsystem.

Required fields:

```
TARGET=<exact target>
SUBSYSTEM=CONSOLE|WINDOWS
EXPECTED_ENTRY=main|wmain|WinMain|wWinMain
CEO_ENTRY=<detected function>
ENTRY_SIGNATURE_COMPAT=PASS|FAIL
```
Gate:

```
GATE=RAWRXD_CEO_ENTRYPOINT_001
VERDICT=PASS|FAIL
```

---

## Batch CEO-03 — Compile Compatibility
Compile CEO main against the real RawrXD headers and definitions.

Classify failures:

```
A = missing header
B = missing declaration
C = incompatible API/signature
D = missing implementation
E = unresolved external
F = duplicate symbol
G = incorrect entry point
H = unrelated target failure
```
Gate:

```
GATE=RAWRXD_CEO_COMPILE_001
CEO_TRANSLATION_UNIT=PASS
COMPILE_ERRORS=0
VERDICT=PASS
```

---

## Batch CEO-04 — Link Compatibility
For every unresolved symbol establish:

```
CEO caller
   ↓
declaration
   ↓
real implementation
   ↓
source file
   ↓
CMake target/library
```
Permitted fixes:

1. Add an existing real implementation.
2. Link the real owning library.
3. Correct an API/signature mismatch.
4. Remove code proven obsolete.
5. Implement genuinely missing functionality.

Forbidden compatibility fixes:

```
empty function bodies
fake return true
fake generated tokens
stub-only symbol definitions
silent fallback
test-only implementation promoted to production
```
Required receipt:

```
GATE=RAWRXD_CEO_LINK_001
UNRESOLVED_EXTERNALS=0
DUPLICATE_SYMBOLS=0
STUB_SYMBOL_RESOLUTIONS=0
VERDICT=PASS
```

---

## Batch CEO-05 — Launch Compatibility
Required:

```
PROCESS_CREATED=1
EARLY_CRASH=0
ENTRYPOINT_ERROR=0
REQUIRED_WINDOW_OR_SERVICE_CREATED=1
```
Gate:

```
GATE=RAWRXD_CEO_LAUNCH_001
VERDICT=PASS
```

---

## Batch CEO-06 — Runtime Initialization
CEO must initialize or deliberately delegate every required production subsystem.

Required receipts:

```
CEO_BOOT_BEGIN
CEO_CONFIG_INIT=PASS
CEO_RUNTIME_INIT=PASS
CEO_DEEP2_INIT=PASS
CEO_AGENT_AUTHORITY_INIT=PASS
CEO_TOOL_AUTHORITY_INIT=PASS
CEO_IDE_OR_SERVER_INIT=PASS
CEO_BOOT_COMPLETE
```
No receipt may be emitted before the underlying operation actually succeeds.

---

## Batch CEO-07 — Deep2 End-to-End Authority
Required call path:

```
CEO
 ↓
Inference Authority
 ↓
Deep2Engine
 ↓
Model/Context
 ↓
Weights
 ↓
Tokenizer
 ↓
Forward
 ↓
Finite Logits
 ↓
Sampler
 ↓
Generated Token
```
Required certification:

```
GATE=RAWRXD_CEO_DEEP2_001

CEO_BOOT=PASS
DEEP2_CREATE=PASS
MODEL_LOAD=PASS
TOKENIZER_READY=PASS
FORWARD_PASS_OK=PASS
LOGITS_FINITE=PASS
GENERATED_TOKEN_COUNT>=1

OLLAMA_USED=0
TEST_ONLY_BACKEND_USED=0
STUB_FALLBACKS=0

VERDICT=PASS
```

---

## Batch CEO-08 — Agent Authority
CEO must orchestrate the authoritative agent chain rather than recreate competing ownership.

Expected responsibility model:

```
PLAN
 ↓
DETECT + PROPOSE
 ↓
AUTHORIZE
 ↓
APPLY
 ↓
RECORD
```
Required proof:

```
CEO_AGENT_PLAN=PASS
TOOL_AUTHORITY_BOUND=PASS
AUTHORIZE_PATH=PASS
APPLY_PATH=PASS
RECORD_PATH=PASS
DUPLICATE_AUTHORITY=0
STUB_FALLBACKS=0
```

---

## Batch CEO-09 — IDE / Chat End-to-End
Required production path:

```
Win32 IDE
 ↓
Chat Send
 ↓
Request Construction
 ↓
Inference Dispatch
 ↓
Deep2
 ↓
Generated Token
 ↓
Streaming Callback
 ↓
Chat Render
```
Certification:

```
GATE=RAWRXD_CEO_CHAT_E2E_001

IDE_LAUNCH=PASS
CHAT_PANEL=PASS
CHAT_SEND=PASS
REQUEST_DISPATCH=PASS
DEEP2_REQUEST=PASS
FIRST_TOKEN=PASS
STREAM_RETURN=PASS
CHAT_RENDER=PASS

GENERATED_TOKEN_COUNT>=1
OLLAMA_USED=0
STUB_FALLBACKS=0

VERDICT=PASS
```

---

## Batch CEO-10 — Shutdown / Lifetime
Test at minimum:

```
normal startup → close

model loaded → close

generation running
 → cancel
 → close

generation finished → close

failed model load → close

agent task executed → close

server active → close
```
Required receipt:

```
GATE=RAWRXD_CEO_SHUTDOWN_001

CEO_SHUTDOWN_BEGIN
ACTIVE_GENERATION=0
WORKERS_JOINED=PASS
MODEL_CONTEXT_DESTROY=PASS
DEEP2_DESTROY=PASS
GPU_DESTROY=PASS
SERVER_STOP=PASS
DUPLICATE_DESTROY_ATTEMPTS=0
CEO_SHUTDOWN_COMPLETE

VERDICT=PASS
```

---

# Final CEO Compatibility Gate
`src/ceo/main.cpp` must **not** be considered compatible merely because it exists, compiles, or links.

Compatibility is certified only when:

```
GATE=RAWRXD_CEO_MAIN_COMPAT_001

ENTRYPOINT=PASS
OLD_MAIN_RESPONSIBILITY_PARITY=PASS

CONFIGURE=PASS
COMPILE=PASS
LINK=PASS
LAUNCH=PASS

RUNTIME_INIT=PASS
DEEP2_INIT=PASS
REAL_FORWARD=PASS
LOGITS_FINITE=PASS
GENERATED_TOKEN_COUNT>=1

AGENT_AUTHORITY=PASS
TOOL_AUTHORITY=PASS

IDE_INIT=PASS
CHAT_DISPATCH=PASS
CHAT_RESPONSE=PASS

CLEAN_SHUTDOWN=PASS

MISSING_REQUIRED_SOURCES=0
REQUIRED_PLACEHOLDER_SOURCES=0
UNRESOLVED_EXTERNALS=0
STUB_FALLBACKS=0
FAKE_SUCCESS_PATHS=0

VERDICT=PASS
```
Until that receipt exists, project status must remain:

```
CEO_MAIN_COMPATIBILITY=UNPROVEN
```

---

# Immediate Execution Order
Order|Batch|Goal|Exit Condition
---|---|---|---
1|CEO-01|Recover old-main contract|Complete responsibility matrix
2|CEO-02|Verify executable entry-point contract|Correct entry type/signature
3|CEO-03|Compile CEO translation unit|Zero CEO compile errors
4|CEO-04|Resolve real link ownership|Zero unresolved externals
5|CEO-05|Launch produced executable|No early crash
6|CEO-06|Verify boot responsibilities|All required subsystems initialized
7|CEO-07|Certify native Deep2 path|Real generated token
8|CEO-08|Certify agent/tool authority|No duplicate/fake authority
9|CEO-09|Certify IDE/chat path|Prompt → Deep2 → rendered response
10|CEO-10|Certify lifetime handling|Clean shutdown
11|FINAL|Freeze compatibility gate|`RAWRXD_CEO_MAIN_COMPAT_001=PASS`

## Engineering Rule
**Do not change the gate to fit the implementation. Change the implementation until it satisfies the gate.**

A green CMake configuration, successful compile, or successful link is not sufficient evidence that `src/ceo/main.cpp` is a valid replacement for the RawrXD production entry point.

This version makes **CEO `main.cpp` compatibility a P0 tracked blocker**, with a concrete batch sequence and a final falsifiable PASS receipt rather than leaving it as a vague “needs verification” item.
