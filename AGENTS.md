---
description: >-
  PassiveRoleNotRoleplay MOTD: per-turn Read gate + continue-ensure passive
  coordinator (Cursor hooks, Deep/Win32/Headless /api/tool). Not roleplay.
  Includes CEO main.cpp compatibility certification tracking
  (RAWRXD_CEO_MAIN_COMPAT_001). Not roleplay.
alwaysApply: true
---

# PassiveRoleNotRoleplay

This file is the **Message of the Day (MOTD)** for Cursor and RawrXD agent execution.

The parent agent is a **passive coordinator**. It does not perform work delegated to a worker. This is execution policy, not character roleplay.

## Per-turn MOTD gate

1. Each new user message: `MOTD_ACK=0`.
2. Until ack: only `Read` / `read_file` / `read_motd` of this file (`.md` / `.mdc`) is allowed.
3. After a successful read this turn: `MOTD_ACK=1` — tools unlock for this turn only.
4. Same gate: Cursor agent tools/hooks/background agents, Deep IDE, Win32IDE, HeadlessIDE, `/api/tool`.

## Continue-ensure triggers

Exact short: `Please continue ensuring`

Exact max: `Please continue ensuring that the streamer is complete and can run agentic`

When either matches:

1. Read this MOTD if not already read this turn.
2. Follow `StreamerAgenticContinueEnsure.mdc` + `MultitaskMode.mdc`.
3. Launch **exactly one** background worker with the max E2E brief.
4. Parent does **not** execute delegated engineering work.
5. Emit coordinator handoff; **end the parent turn**.

Required: `WORKER_COUNT=1` · `PARENT_EXECUTES_DELEGATED_WORK=0` · `PROMOTE=0`

## Fail-closed law

`SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS`

`NOT_RUN != PASS`. Do not invent PASS. Do not alter sealed certification evidence.

## Coordinator output (continue-ensure only)

```
CONTINUE_ENSURE=DISPATCHED
BACKGROUND_WORKERS=1
PARENT_MODE=PASSIVE_COORDINATOR
MOTD_ACK=1
```

## Forbidden

Character roleplay, persona improv, treating "agentic" as fiction/RP, more than one continue-ensure worker, parent continuing delegated work after dispatch.


## Agent Handoff as delegation -> NOT completion

Yes. I'll treat **agent handoff as delegation, not completion**.

For RawrXD/Deep2 work, I'll keep the governing rule as:

```text
HANDOFF_TO_AGENT != DONE

IF work is:
  gapped
  incomplete
  partially implemented
  started but unverified
  delegated but not landed
  landed but not wired
  wired but not exercised
  exercised but not E2E
  E2E but not dispositioned

THEN:
  RESUME_IT
  TRACE_TO_REAL_OWNER
  IMPLEMENT_MISSING_PIECES
  WIRE_REAL_PRODUCT_PATH
  BUILD
  RUN
  VERIFY
  CLOSE_END_TO_END
```

That also means I won't let documentation, a source stub, a smoke witness, an agent result, or an intermediate receipt silently substitute for the actual product path. Existing authority still remains intact—e.g. `R27=LIVE_E2E_PASS`, R28 witness-only/APPLY held, `PROMOTE=0`, and `TIP_CLIMB=HOLD`—unless later real evidence legitimately changes it.

Where I have the necessary repo/files/tools in the current session, I'll continue the work myself rather than merely describing what another agent should do. Where execution access is absent, I'll still carry the implementation/review as far as the available artifacts permit and identify the exact remaining executable gate rather than calling the work finished.

---

# RawrXD Agent Engineering Status

## Source / Build Compatibility Table

| ID | Area | Current Status | Evidence | Missing Proof | Required Gate | Priority |
|---|---|---|---|---|---|:---:|
| SRC-001 | Placeholder source integrity | ⚠️ OPEN | Large number of `src/**/*.cpp` files were previously identified as one-line `// STUB:` placeholders | Confirm which placeholders are still reachable by production targets and remove/restore required implementations | `RAWRXD_SOURCE_INTEGRITY_001` | P0 |
| CMAKE-001 | Missing-source filtering | 🟡 PARTIAL | `rawrxd_filter_missing_sources()` exists in `CMakeLists.txt` | Existing placeholder files are not necessarily rejected because they technically exist | `RAWRXD_CMAKE_SOURCE_TRUTH_001` | P0 |
| CMAKE-002 | Legacy certification isolation | 🟡 PARTIAL | `RAWRXD_BUILD_LEGACY_CERTS` option exists and defaults OFF | Clean configure/build must prove legacy targets no longer contaminate production build | `RAWRXD_CMAKE_CONFIGURE_001` | P1 |
| ENTRY-001 | CEO `main.cpp` compatibility | 🔴 **UNPROVEN** | `CMakeLists.txt` currently substitutes `src/ceo/main.cpp` for the previous `src/main.cpp` | **No evidence yet that `src/ceo/main.cpp` is API-, ABI-, lifecycle-, or behavior-compatible with the RawrXD target** | `RAWRXD_CEO_MAIN_COMPAT_001` | **P0** |
| ENTRY-002 | Process entry point | 🔴 OPEN | CEO source exists | Determine expected `main`, `wmain`, `WinMain`, or `wWinMain` contract and verify CEO implementation matches target subsystem | `RAWRXD_CEO_ENTRYPOINT_001` | P0 |
| ENTRY-003 | Old-main responsibility parity | 🔴 OPEN | Historical `src/main.cpp` can be compared if substantive version exists in Git history | Recover old responsibilities and classify each as `PRESERVED`, `MOVED`, `OBSOLETE`, or `MISSING` | `RAWRXD_CEO_RESPONSIBILITY_PARITY_001` | P0 |
| ENTRY-004 | CEO compile compatibility | 🔴 OPEN | None yet | Prove all CEO includes, declarations, types, and APIs compile against current RawrXD source | `RAWRXD_CEO_COMPILE_001` | P0 |
| ENTRY-005 | CEO link compatibility | 🔴 OPEN | None yet | Prove all symbols used by CEO have real implementations and no unresolved externals | `RAWRXD_CEO_LINK_001` | P0 |
| ENTRY-006 | CEO launch compatibility | 🔴 OPEN | None yet | Build executable and prove it starts without early crash or entry-point mismatch | `RAWRXD_CEO_LAUNCH_001` | P0 |
| ENTRY-007 | CEO subsystem initialization | 🔴 OPEN | None yet | Verify configuration, runtime, Deep2, agent authority, IDE/server, and required services initialize | `RAWRXD_CEO_BOOT_001` | P0 |
| ENTRY-008 | CEO → Deep2 authority | 🔴 OPEN | None yet | Prove CEO reaches the native Deep2 inference path rather than a stub/test-only/legacy backend | `RAWRXD_CEO_DEEP2_001` | P0 |
| ENTRY-009 | CEO real inference | 🔴 OPEN | None yet | Model load → tokenize → forward → finite logits → sampled/generated token | `RAWRXD_CEO_INFERENCE_001` | P0 |
| ENTRY-010 | CEO → agent authority | 🔴 OPEN | Agent architecture exists elsewhere | Prove CEO initializes/reaches the authoritative PLAN → DETECT/PROPOSE → AUTHORIZE/APPLY/RECORD chain | `RAWRXD_CEO_AGENT_AUTHORITY_001` | P1 |
| ENTRY-011 | CEO → IDE/chat E2E | 🔴 OPEN | Chat UI exists | Prove Chat Send → request dispatch → Deep2 → token stream → chat render | `RAWRXD_CEO_CHAT_E2E_001` | P0 |
| ENTRY-012 | CEO shutdown/lifetime | 🔴 OPEN | None yet | Prove cancellation, worker join, Deep2 teardown, GPU teardown, server stop, and clean process exit | `RAWRXD_CEO_SHUTDOWN_001` | P1 |
| LOAD-001 | Parallel GGUF loader substitution | 🔴 UNPROVEN | `gguf_tensor_parallel_loader.cpp` substituted in CMake | No evidence it is API/behavior compatible with the previous tensor loader for all RawrXD callers | `RAWRXD_PARALLEL_LOADER_COMPAT_001` | P0 |
| BUILD-001 | Clean production configure | 🔴 OPEN | CMake edits inspected | Fresh-cache CMake configure has not been certified | `RAWRXD_BUILD_CONFIGURE_001` | P0 |
| BUILD-002 | Clean production compile/link | 🔴 OPEN | None yet | Production target must compile and link from a clean build tree | `RAWRXD_BUILD_RELEASE_001` | P0 |
| BUILD-003 | Stub-free production build | 🔴 OPEN | Stub inventory known to be a concern | Prove required production paths do not resolve through placeholder/no-op/fake-success implementations | `RAWRXD_STUB_FREE_BUILD_001` | P0 |

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
Compare: historical `src/main.cpp` vs current `src/ceo/main.cpp`.

Every previous responsibility must be classified as `PRESERVED` / `MOVED` / `OBSOLETE` / `MISSING`. No `MISSING` responsibility may remain without an explicit resolution.

Matrix rows: Process entry point · CLI/argument parsing · Environment initialization · Logging · Configuration · Runtime creation · Deep2 initialization · Model loading · Agent authority · Tool authority · IDE startup · Server startup · Error propagation · Shutdown/cleanup.

---

## Batch CEO-02 — Entry-Point Contract
Determine the actual CMake executable subsystem:

```
TARGET=<exact target>
SUBSYSTEM=CONSOLE|WINDOWS
EXPECTED_ENTRY=main|wmain|WinMain|wWinMain
CEO_ENTRY=<detected function>
ENTRY_SIGNATURE_COMPAT=PASS|FAIL
```

Gate: `GATE=RAWRXD_CEO_ENTRYPOINT_001 · VERDICT=PASS|FAIL`

---

## Batch CEO-03 — Compile Compatibility
Compile CEO main against the real RawrXD headers and definitions.

Failure classes: `A`=missing header · `B`=missing declaration · `C`=incompatible API/signature · `D`=missing implementation · `E`=unresolved external · `F`=duplicate symbol · `G`=incorrect entry point · `H`=unrelated target failure.

Gate: `GATE=RAWRXD_CEO_COMPILE_001 · CEO_TRANSLATION_UNIT=PASS · COMPILE_ERRORS=0 · VERDICT=PASS`

---

## Batch CEO-04 — Link Compatibility
For every unresolved symbol establish: CEO caller → declaration → real implementation → source file → CMake target/library.

**Permitted fixes:** add an existing real implementation · link the real owning library · correct an API/signature mismatch · remove code proven obsolete · implement genuinely missing functionality.

**Forbidden fixes:** empty function bodies · fake `return true` · fake generated tokens · stub-only symbol definitions · silent fallback · test-only implementation promoted to production.

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

```
PROCESS_CREATED=1
EARLY_CRASH=0
ENTRYPOINT_ERROR=0
REQUIRED_WINDOW_OR_SERVICE_CREATED=1
```

Gate: `GATE=RAWRXD_CEO_LAUNCH_001 · VERDICT=PASS`

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
Required call path: `CEO → Inference Authority → Deep2Engine → Model/Context → Weights → Tokenizer → Forward → Finite Logits → Sampler → Generated Token`

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
CEO must orchestrate the authoritative agent chain: `PLAN → DETECT + PROPOSE → AUTHORIZE → APPLY → RECORD`

Required proof: `CEO_AGENT_PLAN=PASS · TOOL_AUTHORITY_BOUND=PASS · AUTHORIZE_PATH=PASS · APPLY_PATH=PASS · RECORD_PATH=PASS · DUPLICATE_AUTHORITY=0 · STUB_FALLBACKS=0`

---

## Batch CEO-09 — IDE / Chat End-to-End
Required production path: `Win32 IDE → Chat Send → Request Construction → Inference Dispatch → Deep2 → Generated Token → Streaming Callback → Chat Render`

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
Test: normal startup → close · model loaded → close · generation running → cancel → close · generation finished → close · failed model load → close · agent task executed → close · server active → close.

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

| Order | Batch | Goal | Exit Condition |
|:---:|---|---|---|
| 1 | CEO-01 | Recover old-main contract | Complete responsibility matrix |
| 2 | CEO-02 | Verify executable entry-point contract | Correct entry type/signature |
| 3 | CEO-03 | Compile CEO translation unit | Zero CEO compile errors |
| 4 | CEO-04 | Resolve real link ownership | Zero unresolved externals |
| 5 | CEO-05 | Launch produced executable | No early crash |
| 6 | CEO-06 | Verify boot responsibilities | All required subsystems initialized |
| 7 | CEO-07 | Certify native Deep2 path | Real generated token |
| 8 | CEO-08 | Certify agent/tool authority | No duplicate/fake authority |
| 9 | CEO-09 | Certify IDE/chat path | Prompt → Deep2 → rendered response |
| 10 | CEO-10 | Certify lifetime handling | Clean shutdown |
| 11 | FINAL | Freeze compatibility gate | `RAWRXD_CEO_MAIN_COMPAT_001=PASS` |

## Engineering Rule

**Do not change the gate to fit the implementation. Change the implementation until it satisfies the gate.**

A green CMake configuration, successful compile, or successful link is not sufficient evidence that `src/ceo/main.cpp` is a valid replacement for the RawrXD production entry point.
