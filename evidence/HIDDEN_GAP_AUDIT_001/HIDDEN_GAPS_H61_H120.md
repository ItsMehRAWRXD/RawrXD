# HIDDEN_GAPS_H61_H120 — AUDIT TRACK D

```
ASOF_UTC=2026-11-09T12:40:00Z
MOTD_ACK=1
TRACK=D
WORKSPACE=F:\rawrxd
CONTROLLING_TIP=CC79
CONTROLLING_SHA=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
FROZEN_A4F=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
A4F_IMMUTABLE=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY_ESTIMATE=82_PERCENT_UNCHANGED
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
INVENT_PASS=0
INVENT_CONFIRMED_DEFECT=0
NO_CROSS_SHA_PASS_INHERITANCE=1
ENTRIES=H61..H120
CONFIRMED_COUNT=0
UNVERIFIED_COUNT=19
INVESTIGATE_COUNT=38
N_A_OUT_OF_SCOPE_COUNT=3
```

## Status vocabulary (fail-closed)

| Status | Meaning |
|--------|---------|
| CONFIRMED | Supported by reported **failure** evidence on an identified path/SHA |
| UNVERIFIED | Required behavior for product-final / PR acceptance **not demonstrated** (`NOT_RUN` / OPEN gates) |
| INVESTIGATE | Plausible failure mechanism; must be checked; **≠** confirmed defect |
| N_A_OUT_OF_SCOPE | Outside Windows daily-driver minimum until approved 100% product spec mandates it |

```
INVESTIGATE ≠ FAIL
NOT_RUN ≠ PASS
OPEN_PR ≠ DEFECTIVE_IMPL
SOURCE_WIRED ≠ RUNTIME_REACHED ≠ TOKEN_SURVIVED ≠ PERFORMANCE_PASS
```

## Cross-link authority

| Ref | Role | State (this audit) |
|-----|------|--------------------|
| [Issue #49](https://github.com/ItsMehRAWRXD/RawrXD/issues/49) | Product-final E2E scenario (decisive maturity yardstick) | OPEN; receipt keys NOT_PROVEN |
| [Issue #50](https://github.com/ItsMehRAWRXD/RawrXD/issues/50) | Certification ladder Layers 0–10 | OPEN; L0 integration seal pending; L1–10 blocked/pending |
| [Issue #57](https://github.com/ItsMehRAWRXD/RawrXD/issues/57) | 45 gates = Native IDE (15) + Compiler/Slingshot (15) + GPU/Release (15) | OPEN; do **not** arithmetically add to 78 or 120 |
| [PR #75](https://github.com/ItsMehRAWRXD/RawrXD/pull/75) | Native compiler/linker (37 local claimed; 16 linker NOT_EXECUTED) | OPEN DRAFT; MERGEABLE API ≠ merge auth |
| [PR #76](https://github.com/ItsMehRAWRXD/RawrXD/pull/76) | Deep2 consolidation | OPEN DRAFT; CONFLICTING; DO NOT MERGE |
| [PR #77](https://github.com/ItsMehRAWRXD/RawrXD/pull/77) | IDE product path (ConPTY / inference UI / Problems / Output) | OPEN; CONFLICTING; `PR77_ACCEPTANCE_001` MERGE_READY=0 |
| [PR #78](https://github.com/ItsMehRAWRXD/RawrXD/pull/78) | AgentSession lifecycle / cancel / restore | OPEN; CONFLICTING; `PR78_ACCEPTANCE_001` all runtime gates NOT_RUN |
| [PR #79](https://github.com/ItsMehRAWRXD/RawrXD/pull/79) | ExtensionHost runtime | OPEN; CONFLICTING; `PR79_ACCEPTANCE_001` MERGE_READY=0 |

Local ledgers (do not inherit PASS across SHA):

- `FULL_FEATURE_ONESHOT_001\MASTER_STATUS.md` — Autonomous coding=NOT_RUN; Deep2=PARTIAL; Ollama=NOT_RUN; Build 3014 on CC79 FAIL
- `FULL_FEATURE_ONESHOT_001\FINISH25_MATRIX.md` — historical 19/25; current oneshot **4/25**
- `FULL_FEATURE_FINAL_COMPLETION_001\INTEG004_ACCEPTANCE_DISPOSITION.md` — Problems PASS on `47451F24…` only; CC79 Problems FAIL; tip move unauthorized
- `HIDDEN_GAP_AUDIT_001\GITHUB_PR_ISSUE_INVENTORY.md` — Track B inventory

### Issue #49 product-final mapping (H61–H120 relevance)

| #49 receipt key | Primary H IDs |
|-----------------|---------------|
| TOOL_AUTHORITY / REAL_TOOL_CALL / RESULT_REINJECTION / AGENT_CONTINUATION | H61–H67, H72 |
| REAL_SOURCE_EDIT / BUILD_FAILURE_RECOVERY / FINAL_BUILD / FINAL_TESTS | H62–H65, H72, H120 |
| MULTI_AGENT_REVIEW | H70 |
| IDE_GIT | H71, H110 |
| GPU_RUNTIME / GPU_FORWARD / FINITE_LOGITS / GENERATION / LOCAL_MODEL_LOAD | H73–H90 |
| STUB_PROVIDERS=0 / STUB_FALLBACKS=0 / SYNTHETIC_RECEIPTS=0 | H84, H97, H102, H115–H116 |
| CLEAN_MACHINE_REPRODUCIBLE / CI_REPRODUCIBLE | H98–H106, H119 |
| Full autonomous loop | **H120** (decisive) |

### Issue #57 scope carve-out (Windows daily-driver)

Mandatory for daily-driver / Issue #49 path: Group A IDE gates that touch Win32 panels, agent edit→build→test, and Group C **single-GPU** correctness needed for local model on controlling Windows host.

**N_A_OUT_OF_SCOPE until 100% enterprise spec explicitly mandates** (still tracked under #57; never sum into daily-driver blocker count):

- #57 B13 ELF/Linux host contracts
- #57 B14 Mach-O/macOS/iOS contracts
- #57 B15 Android ABI/APK contracts
- #57 C08–C09 dual-GPU / multi-GPU synchronization as **mandatory** daily-driver blockers
- Marketing/docs claims of multi-OS native compilers without Windows PE proof (ties H114)

PE/COFF Windows linker and MSVC-hosted compile paths remain **in-scope INVESTIGATE/UNVERIFIED** (PR #75; #57 B11–B12), distinct from ELF/Mach-O/Android.

---

## Band H61–H72 — AgentSession / autonomous coding

Evidence base: `PR78_ACCEPTANCE_001\RECEIPT.md` (AGENT_SESSION_LIFECYCLE/TOOL_EXECUTION/CANCEL_RECOVERY=NOT_RUN; EXE NOT_BUILT); MASTER_STATUS Autonomous coding=NOT_RUN; PR #78 OPEN CONFLICTING. **CONFIRMED_COUNT=0** in this band (no SHA-specific AgentSession runtime FAIL receipt found).

| ID | Hidden gap | Status | Evidence / justification | Dedupe / cross-links |
|----|------------|--------|--------------------------|----------------------|
| H61 | Tool permission checks bypassed by alternate entry points | INVESTIGATE | No bypass FAIL receipt; #49 TOOL_AUTHORITY required | PR78; #49 TOOL_AUTHORITY; #50 L3 |
| H62 | Agent edits wrong workspace or file | INVESTIGATE | No wrong-file FAIL; REAL_SOURCE_EDIT NOT_RUN | PR78; #49 REAL_SOURCE_EDIT |
| H63 | Partial writes leave corrupted source | INVESTIGATE | No corruption FAIL receipt | PR78; #57 A15 rollback |
| H64 | Failed edits cannot be rolled back | UNVERIFIED | Rollback required (#57 A15 / agent snapshot); not demonstrated on CC79/PR78 tip | #57 A15; #49 BUILD_FAILURE_RECOVERY |
| H65 | Agent reports build success without executable evidence | INVESTIGATE | No agent false-success receipt. CC79 Build 3014 `exit=-1` is **IDE build HWND** FAIL — different subsystem; do not auto-map as AgentSession CONFIRMED | MASTER_STATUS Build FAIL; PR77/PR78 separate |
| H66 | Agent loops indefinitely after repeated failures | INVESTIGATE | No hang FAIL receipt; loop bound unproven | #49 AGENT_CONTINUATION |
| H67 | Tool execution blocks model streaming | INVESTIGATE | Streaming+tool overlap NOT_RUN | PR77 inference UI; PR78 tools |
| H68 | Concurrent agents overwrite one another's changes | INVESTIGATE | Multi-writer race untested; single-agent daily path still needs proof | #49 MULTI_AGENT_REVIEW adjacent |
| H69 | Agent state cannot recover after application restart | UNVERIFIED | PR78 Kill/Restore gates NOT_RUN; T10 recovery PASS is **not** AgentSession restore PASS | PR78; Finish-25 T10 ≠ H69 |
| H70 | Review agent approves untested changes | UNVERIFIED | #49 MULTI_AGENT_REVIEW not demonstrated | #49; #50 L3+ |
| H71 | Git commit includes unrelated modifications | INVESTIGATE | No dirty-tree FAIL; #49 IDE_GIT required | #49 IDE_GIT; H110 |
| H72 | Agent reports task completion before final tests finish | UNVERIFIED | #49 FINAL_TESTS / product-final loop NOT_RUN | #49 FINAL_TESTS; H120 |

---

## Band H73–H90 — Inference / Ollama / Deep2 / GPU

Evidence base: MASTER_STATUS Local model=PARTIAL/NOT_RUN (Deep2 PARTIAL; Ollama NOT_RUN); PR #76 HELD/CONFLICTING; #50 L1 Deep2 blocked; #57 Group C open; PROMOTE=0. **CONFIRMED_COUNT=0**.

| ID | Hidden gap | Status | Evidence / justification | Dedupe / cross-links |
|----|------------|--------|--------------------------|----------------------|
| H73 | Model selector points to wrong model or backend | UNVERIFIED | Backend identity receipts absent on CC79 product path | #49 LOCAL_MODEL_LOAD; PR76 |
| H74 | Ollama streaming parser mishandles fragmented JSON | UNVERIFIED | Ollama=NOT_RUN on controlling ledger | MASTER_STATUS |
| H75 | Inference cancellation leaves active GPU work | UNVERIFIED | Cancel+GPU cleanup NOT_RUN | PR77/PR78 cancel; #57 C |
| H76 | Backend shutdown leaks threads or memory | INVESTIGATE | No leak trend receipt on release EXE | Lifecycle graph |
| H77 | Model loading succeeds but inference produces invalid output | UNVERIFIED | GPU_FORWARD / FINITE_LOGITS / GENERATION NOT_PROVEN for #49 | #49; #50 L1–L2 |
| H78 | GPU offload counters differ from actual executed operations | INVESTIGATE | Counter-vs-reality audit not sealed on CC79 | #57 C04–C05 |
| H79 | Quantized kernels produce incorrect numerical results | UNVERIFIED | #57 C03 Q4_K/Q5_K/Q6_K/F32 oracle gates open; PROMOTE=0 | #57 C; PR76 |
| H80 | KV-cache rollback corrupts subsequent generations | INVESTIGATE | No corruption FAIL; required for long sessions | #50 / Deep2 |
| H81 | Long-context allocation exceeds available VRAM/RAM | INVESTIGATE | Bound/fail-closed behavior unproven on product EXE | #57 C06–C07 |
| H82 | Multi-GPU partitioning causes incorrect tensor placement | N_A_OUT_OF_SCOPE | Dual-GPU (#57 C08–C09) enterprise/multi-device; **not** mandatory Windows single-GPU daily-driver blocker. Retain under #57 | #57 C08–C09 |
| H83 | GPU synchronization serializes supposedly parallel execution | N_A_OUT_OF_SCOPE | Multi-device parallel sync same carve-out as H82; single-GPU fence correctness stays INVESTIGATE under H78/H79 | #57 C09 |
| H84 | Fallback paths silently execute on CPU | INVESTIGATE | Silent CPU fallback would violate #49 GPU_FORWARD / STUB_FALLBACKS=0 — unproven either way | #49; #57 C05 |
| H85 | Driver incompatibility mistaken for a model defect | INVESTIGATE | No sealed driver-vs-model disposition on CC79 | GPU/Release |
| H86 | Model switching retains stale tokenizer or sampler state | INVESTIGATE | Switch/reload hygiene NOT_RUN | PR76; H73 |
| H87 | GPU device loss cannot be recovered without restarting the IDE | INVESTIGATE | Device-lost recovery path unproven | Reliability |
| H88 | Benchmark throughput excludes prefill/waits/transfers without disclosure | INVESTIGATE | #57 C12 forbids synthetic kernel TPS as product claim; disclosure audit open | #57 C12–C13; #50 L9 |
| H89 | Model-format and GGUF shard validation accepts corrupt data | INVESTIGATE | #57 C10 matrix open; no corrupt-accept FAIL sealed here | #57 C10 |
| H90 | Local-only operation inadvertently depends on external services | UNVERIFIED | Offline/local-only #49 requirement not demonstrated on clean machine | #49 CLEAN_MACHINE; #57 C15 |

---

## Band H91–H106 — Security / reliability / release integrity

Evidence base: no SHA-specific security FAIL receipts elevated to CONFIRMED this turn; CI often fails **before** steps (runner empty) — infra NOT_RUN/FAIL, not “green without tests.” CERTIFIED=0 / PROMOTE=0 held. Historical RawrXDA stub inventories are **leads only**.

| ID | Hidden gap | Status | Evidence / justification | Dedupe / cross-links |
|----|------------|--------|--------------------------|----------------------|
| H91 | Workspace path traversal through agent or extension tools | INVESTIGATE | No traversal FAIL; containment required for tools | PR78/PR79; #49 TOOL_AUTHORITY |
| H92 | Untrusted model output bypasses tool authorization | INVESTIGATE | Same as H61 family; NOT_RUN | #49 TOOL_AUTHORITY |
| H93 | Shell argument handling allows unintended command execution | INVESTIGATE | PR75 notes argv subprocess (no shell) on adapter — IDE agent shell path still needs proof | PR75; PR78 ToolShell |
| H94 | Sensitive values leak into logs or crash dumps | INVESTIGATE | Dump/log redaction unproven | Reliability |
| H95 | Extension IPC accepts unauthorized commands | INVESTIGATE | PR79 IPC handshake RUNTIME NOT_RUN | PR79 |
| H96 | Downloaded/installed extensions lack appropriate validation | INVESTIGATE | Marketplace/validation not certified | PR79 |
| H97 | Security-sensitive production paths use placeholder cryptography | INVESTIGATE | Historical stub inventory = lead ≠ today’s CONFIRMED | Historical RawrXDA note |
| H98 | Release binaries depend on undeclared DLLs | UNVERIFIED | Clean-machine / dependency closure open (#57 A04/C15) | #49 CLEAN_MACHINE; packaging |
| H99 | Installer writes outside intended directories | INVESTIGATE | Installer path audit open; T24 PARTIAL_STAGE_ONLY | Finish-25 T24 |
| H100 | Uninstall or rollback destroys user data | INVESTIGATE | Uninstall safety NOT_RUN | Packaging |
| H101 | Crash recovery replays unsafe or incomplete operations | INVESTIGATE | T10 recovery PASS ≠ unsafe-replay proof for agent edits | Finish-25 T10; H69 |
| H102 | Build artifacts or test receipts accepted without provenance | INVESTIGATE | Multi-track evidence risk gated by NO_CROSS_SHA; still audit every new receipt | Law; H106 |
| H103 | GitHub Actions reports success without executing mandatory tests | INVESTIGATE | Observed pattern is **failure / empty runner / 0 steps** (#57; PR75/76 CI) — not a proven false-green. Exact H103 wording not CONFIRMED | #57 A01; PR75/76 |
| H104 | LFS or branch divergence leaves release source incomplete | INVESTIGATE | PR76 divergence/conflicts are **PR state**, not incomplete release tree on CC79 package | PR76 CONFLICTING |
| H105 | Signed artifact differs from the tested executable | UNVERIFIED | Signed≠tested pairing not demonstrated; CERTIFIED=0 | #57 C15; release |
| H106 | Final release certified using evidence from multiple SHAs | INVESTIGATE | CERTIFIED=0 so wrongful multi-SHA cert has **not** occurred; cross-SHA confusion (19/25 vs 4/25 vs CC79 vs INTEG004) is controlled risk | CONTROLLER; INTEG004; Finish-25 |

---

## Band H107–H120 — Product-completion gaps

Evidence base: #57 Group A LSP/GhostText/browser/debugger/agent rollback open; MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED; Autonomous coding=NOT_RUN; #49 OPEN.

| ID | Hidden gap | Status | Evidence / justification | Dedupe / cross-links |
|----|------------|--------|--------------------------|----------------------|
| H107 | LSP handshake succeeds but diagnostics/completion do not work | UNVERIFIED | #57 A11 open; no CC79 LSP E2E PASS | #57 A11 |
| H108 | GhostText appears but accept/cancel edits the wrong range | UNVERIFIED | #57 A12 open | #57 A12 |
| H109 | Native browser renders but lacks origin/navigation isolation | UNVERIFIED | #57 A13 open | #57 A13 |
| H110 | Git operations modify an unintended repository or branch | INVESTIGATE | No wrong-repo FAIL; #49 IDE_GIT required | #49; H71 |
| H111 | Snapshot restoration fails after a partially completed edit | UNVERIFIED | #57 A15 open; overlaps H64 | #57 A15; H64 |
| H112 | Settings persist but are not applied to active components | INVESTIGATE | Apply-on-live-components unproven | Settings |
| H113 | Feature registry advertises commands with no real backend | INVESTIGATE | Command-graph audit pending (five-layer RE) | Menu dispatch family |
| H114 | Cross-platform functionality claimed without native execution | N_A_OUT_OF_SCOPE | ELF/Linux, Mach-O/macOS, Android (#57 B13–B15) are **not** Windows daily-driver mandatory blockers. #57 release law forbids claiming those targets until linked+run | #57 B13–B15; PR75 |
| H115 | Performance tests use synthetic kernels instead of real model decode | INVESTIGATE | #57 C12 open; synthetic≠PASS law | #57 C12; #50 L9 |
| H116 | Release documentation describes capabilities absent from the binary | INVESTIGATE | Docs-vs-binary audit open | Release |
| H117 | Acceptance tests omit negative and recovery scenarios | UNVERIFIED | Many recovery/negative paths NOT_RUN on current oneshot (Finish-25 current 4/25) | Finish-25; oneshot gates |
| H118 | Multiple passing components fail when operated simultaneously | UNVERIFIED | Integrated simultaneous operation **not demonstrated** (NOT_DEMONSTRATED ≠ measured simultaneous FAIL). Do not invent CONFIRMED | CONTROLLER; #49 |
| H119 | Test fixtures conceal environment or dependency requirements | INVESTIGATE | Fixture/env concealment risk; clean-clone #49 requires proof | #49 CLEAN_CLONE |
| H120 | Final product acceptance omits the complete autonomous coding loop | UNVERIFIED | Autonomous coding=NOT_RUN; PRODUCT_PASS=0; #49 OPEN / receipt keys NOT_PROVEN. Required milestone absent — **not** a runtime FAIL receipt, so not CONFIRMED | #49; MASTER_STATUS; decisive maturity gate |

### Explicit N_A rows (multi-platform / multi-GPU vs Windows daily-driver)

| ID | Why N_A_OUT_OF_SCOPE |
|----|----------------------|
| H82 | Dual/multi-GPU partitioning mandatory only if enterprise #57 C08 promoted into approved 100% daily-driver spec |
| H83 | Multi-device parallel sync same carve-out (single-GPU fence work remains via H78/H79) |
| H114 | Cross-OS native compiler/runtime claims (#57 B13–B15) outside Windows MSVC/PE daily-driver minimum |

Related #57 aliases for master merge (not extra H rows): **B13, B14, B15, C08, C09** → N_A_OUT_OF_SCOPE for daily-driver blocker set.

---

## Band rollup (Track D only)

| Band | IDs | CONFIRMED | UNVERIFIED | INVESTIGATE | N_A |
|------|-----|-----------|------------|-------------|-----|
| AgentSession | H61–H72 | 0 | 4 | 8 | 0 |
| Inference/GPU | H73–H90 | 0 | 6 | 10 | 2 |
| Security/release | H91–H106 | 0 | 2 | 14 | 0 |
| Product-completion | H107–H120 | 0 | 7 | 6 | 1 |
| **Total H61–H120** | 60 | **0** | **19** | **38** | **3** |

```
CONFIRMED_BLOCKERS_H61_H120=0
N_A_OUT_OF_SCOPE_H_ROWS=H82,H83,H114
N_A_ISSUE57_ALIASES=B13,B14,B15,C08,C09
```

## What would promote an entry to CONFIRMED

Only a SHA-identified runtime/acceptance receipt showing the named failure (or a sealed FAIL gate). Examples:

- PR78 tip EXE: cancel returns while tools continue → H61/H75 family CONFIRMED
- #49 run: FINAL_TESTS never executed but agent emits completion → H72 CONFIRMED
- Measured dual-GPU wrong placement **after** multi-GPU enters approved daily-driver spec → revisit H82 then CONFIRMED

Until then: keep CONFIRMED=0 in this track.

## Disposition

```
TRACK_D=COMPLETE_FOR_MERGE_PREP
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
CC79_CONTROLLING=1
A4F_IMMUTABLE=1
NEXT=Apply DEDUPE_RULES.md when merging into MASTER_HIDDEN_GAP_REGISTER.md
DECISIVE_MILESTONE=Issue_49_single_SHA_product_final
```
