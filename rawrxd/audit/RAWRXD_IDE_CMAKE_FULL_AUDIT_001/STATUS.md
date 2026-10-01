# RawrXD IDE CMake Audit — Completion Checklist

> Canonical status section. Replaces the previous dash-style status list.
> Rule: **discovery/audit work that actually happened is checked; implementation or
> certification that has not happened remains unchecked.** A "found the defect"
> checkbox is never upgraded to a "fixed the defect" checkbox.

## Verdict keys (two separate verdicts, do not conflate)

```ini
RAWRXD_IDE_CMAKE_FULL_AUDIT_001=IN_PROGRESS   # this audit/closure work
PRODUCT_COMPLETION=FAIL                       # the product itself
```

---

## A. Deep2 lifecycle diagnosis

- [x] Fresh-process prompt-length hypothesis tested through **575 prompt tokens**
- [x] `RAWRXD_CPU_PROMPT_LENGTH_LIMIT=REFUTED`
- [x] Same-engine second-generation failure reproduced
- [x] Root cause localized to generation lifecycle / stale KV state
- [x] D2 identified: KV cache is not reset between independent generations
- [x] D1 identified: `completed` can disagree with `GenerationStatus`
- [x] D3 identified: EOS/control-token termination is incomplete
- [x] Model-quality judgment withdrawn until D2/D1/D3 are repaired
- [x] Repair order frozen as **D2 → D1 → D3**
- [x] Acquire exclusive `RAWRXD_DEEP2_GENERATION_LIFECYCLE_001` writer authority
- [x] Implement D2 at the canonical independent-generation boundary
- [x] Pass 4 sequential generations on **one engine instance**
- [x] Prove no stale-KV exception across generations 1–4
- [ ] Implement D1 result-state correction
- [ ] Prove `ForwardFailure + completed=true` is impossible
- [ ] Prove `Cancelled + completed=true` is impossible
- [ ] Prove a zero-token failed generation cannot be reported successful
- [ ] Implement D3 model-specific EOS/control termination
- [ ] Define sampled-token vs emitted-token accounting
- [ ] Pass EOS termination regression
- [ ] Re-run one-shot semantic-copy probe
- [ ] Re-run agent-shaped observation probe
- [ ] Re-run real `MODEL → TOOL → OBSERVATION → MODEL`
- [ ] Certify semantic groundedness only after the above passes

The attachments explicitly establish D2 as the blocker and leave D1/D3 unresolved; they also
require the four-generation same-engine regression before lifecycle correctness can be called
closed.

**One item corrected from the supplied text, with evidence.** The supplied checklist left
"Acquire exclusive `RAWRXD_DEEP2_GENERATION_LIFECYCLE_001` writer authority" unchecked. It was
in fact acquired in this session, before the audit freeze, and every field below is measured
tool output rather than assertion:

```ini
LEASE_AUTHORITY=RAWRXD_SINGLE_WRITER_AUTHORITY_001
LEASE_FILE=F:\~dev\.rawrxd\leases\writer.lease
LEASE_PID=30252
LEASE_NONCE=5712953110738933491
LEASE_EXPECTED_HEAD=a078e3b87be6b22ed1fa6fce6a20bfdd980e4441
VALIDATE_HEAD_AT_ACQUIRE=1
LEASE_AUTHORIZED_PATH_COUNT=4
  rawrxd/src/deep2/Deep2Engine.h
  rawrxd/src/deep2/Deep2Engine.cpp
  rawrxd/src/deep2/Tokenizer.hpp
  rawrxd/tools/deep2_generation_lifecycle_test.cpp
PRIOR_LEASE_RELEASED_VIA=its own stop file (PID 23572, RAWRXD_STUB_RECONCILIATION_001)
```

Acquiring the lease is not the same as performing D2. Every D2–D3 row below it stays unchecked.

### D2 closed on measurement — Batch 01

`batches/BATCH_01_DEEP2_LIFECYCLE_RECEIPT.md`. Four generations on one engine
instance, `VERDICT=PASS`, `EXITCODE=0`, `cpu_forward_exception` occurrences = 0.
The D2 reset binding at `Deep2Engine.cpp:3671` already existed before this batch;
what was missing was the measurement. The driver shipped in this batch with a
false-positive KV predicate, which was corrected and re-run.

```ini
D2_KV_RESET=PASS
ENGINE_INSTANCE_COUNT=1
GEN1=PASS  GEN2=PASS  GEN3=PASS  GEN4=PASS
STALE_KV_EXCEPTIONS=0
TOKENS_WRITTEN_BY_PRIOR_GENERATIONS=74
KV_LENGTH_AFTER_LAST_GENERATION=16
GENERATION_INHERITED_KV_FROM_PRIOR_GENERATIONS=0
ITEM_03_RESET_CLEARS_KV_ENTRIES=FAIL_LITERAL   # clear(false): position fresh, bytes stale
D1_RESULT_CONTRACT=OPEN                         # completed computed before status is decided
D3_EOS_TERMINATION=NOT_FIXED                    # D[0] ran to the 48-token ceiling
TOKEN_DECODE_RETURNS_CR=NOT_FIXED               # 3 of 4 generations decoded to 0x0D
```

D1 and D3 rows stay unchecked. The four D1 predicate counters read 0 in Batch 01
because that run had no failure — that is a measurement of the run, not a proof
that the forbidden states are unreachable, and source reading confirms
`ForwardFailure + completed=true` is still reachable at `Deep2Engine.cpp:4118`.

---

## B. CMake configuration and source coverage audit

- [x] Real CMake configure output inspected
- [x] **225** `WIN32IDE_SOURCES` missing-source warnings measured
- [x] All 225 warning paths verified unique
- [x] Duplicate warning count verified as 0
- [x] Static-parser result of 221 rejected as non-authoritative for this configured build
- [x] Rule established: **real configure log outranks static CMake simulation**
- [x] Total implementation files inventoried: **1968**
- [x] CMake-bound implementation files measured: **616**
- [x] CMake-unbound implementation files measured: **1271**
- [x] Ambiguous implementation files measured: **81**
- [x] Missing-but-bound source references measured: **360**
- [x] Seven orphan `CMakeLists.txt` files identified
- [x] Seventeen targets inside those orphan CMake trees identified as unconfigured
- [x] Four dead `add_subdirectory()` paths identified
- [x] `src/runtime` dead-subdirectory condition identified
- [x] `tests` dead-subdirectory condition identified
- [x] `src/tools` dead-subdirectory condition identified
- [x] `src/validation` dead-subdirectory condition identified
- [ ] Reconcile all 225 shipping `WIN32IDE_SOURCES` omissions
- [ ] Classify every one of the 1271 unbound implementation files as intentionally excluded or incorrectly unbound
- [ ] Resolve all 81 ambiguous bindings
- [ ] Resolve all 360 missing-bound references
- [ ] Connect or explicitly retire all seven orphan CMake trees
- [ ] Connect or explicitly retire all seventeen unreachable targets
- [ ] Remove every silent `EXISTS` gate that hides a required production subsystem
- [ ] Reconfigure and prove **MISSING_BOUND=0** for the intended shipping configuration

The direct configure-log measurement is **225 distinct dropped paths**. The source-coverage
ledger records **1968 total / 616 bound / 1271 unbound / 81 ambiguous / 360 missing-bound**.

---

## C. `rawr` agentic CLI CMake binding

- [x] `RawrAgenticCli.fragment.cmake` inspected
- [x] Missing `src/cli/rawr_main.cpp` gate identified
- [x] Consequence identified: **85 declared agentic CLI sources are silently omitted**
- [x] `target_sources(rawr ...)` suppression identified
- [x] Configure can remain apparently clean while the agentic CLI is absent
- [ ] Decide the canonical production CLI entrypoint
- [ ] Restore/bind the canonical entrypoint without creating a competing agent subsystem
- [ ] Bind the required real agentic CLI sources into `rawr`
- [ ] Reconfigure and prove the 85-source surface is no longer silently dropped
- [ ] Compile `rawr`
- [ ] Link `rawr`
- [ ] Execute `rawr run modelname ...`
- [ ] Execute `rawr agent ...`
- [ ] Verify both paths use the intended common runtime/authority core

The current audit specifically found that the missing `rawr_main.cpp` causes the 85-source
agentic CLI surface to be skipped without a CMake error.

---

## D. Shipping Win32 IDE target topology

- [x] `win32ide_strict/CMakeLists.txt` audited for reachability
- [x] Confirmed shipping root configure does **not** reach `win32ide_strict`
- [x] `RawrXD-Win32IDE-Tests` therefore classified unreachable from shipping root
- [x] `RawrXD-Layer0-Final-Evidence` therefore classified unreachable from shipping root
- [ ] Establish one canonical Win32 IDE CMake authority
- [ ] Eliminate competing/unreachable IDE target definitions
- [ ] Bind all intended IDE test targets from the canonical root
- [ ] Bind all intended certification targets from the canonical root
- [ ] Prove `cmake --build ... --target help` exposes every intended shipping/test target
- [ ] Prove no production certification depends on an unreachable CMake subtree

The audit explicitly records `win32ide_strict/CMakeLists.txt` as unreachable and counts seven
unprocessed CMake trees / seventeen unconfigured targets.

---

## E. Build methodology

- [x] Configure output retained as primary evidence
- [x] Build compile-error result captured
- [x] Deviation recorded: Batch 06 used default MSBuild parallelism rather than `--parallel 1`
- [ ] Repeat the authoritative final build with deterministic/specified parallelism
- [ ] Preserve complete compiler diagnostics by target
- [ ] Verify every intended target compiles
- [ ] Verify every intended target links
- [ ] Verify no required target disappeared through conditional CMake filtering
- [ ] Generate final target-by-target build receipt

The audit explicitly records the Batch 06 parallelism deviation rather than concealing it.

---

## F. Win32 IDE runtime certification

- [x] IDE binary generation has been exercised
- [x] Runtime smoke testing was attempted
- [x] Audit records that the prior smoke ended by force termination
- [ ] Launch the exact freshly audited executable
- [ ] Verify executable SHA against the build being certified
- [ ] Verify normal Win32 initialization
- [ ] Verify editor surface
- [ ] Verify explorer surface
- [ ] Verify menu/command dispatch
- [ ] Verify terminal/output surface
- [ ] Verify diagnostics surface
- [ ] Verify model-selection surface
- [ ] Verify IDE chat reaches the real local inference backend
- [ ] Verify streaming response
- [ ] Verify cancellation
- [ ] Verify clean user-requested shutdown
- [ ] Verify no process/thread survives normal shutdown
- [ ] Replace force-termination evidence with normal-shutdown evidence
- [ ] Produce final runtime receipt

The current audit specifically states that clean shutdown was **not** exercised because the smoke
ended in forced termination.

### F.1 Measured, deliberately not checked

The F rows above are left unchecked on purpose. They were measured, but the measurements do not
satisfy the verifications named in the rows, so promoting them would overstate the evidence.

```ini
MEASURED_EXE=F:\~dev\rawrxd\build_ide_audit\bin\Release\RawrXD-Win32IDE.exe
MEASURED_EXE_BYTES=20457984
MEASURED_EXE_LASTWRITE_UTC=2026-09-30T19:00:14Z
MEASURED_PROCESS_ALIVE=1
MEASURED_RESPONDING=1
MEASURED_MAIN_WINDOW_HANDLE=26543562      (non-zero => a top-level window exists)
MEASURED_MAIN_WINDOW_TITLE=RawrXD Win32 IDE
MEASURED_THREAD_COUNT=5
MEASURED_WORKING_SET_MB=19.3
MEASURED_UPTIME_SEC=12
MEASURED_TERMINATION=FORCED_BY_AUDIT
```

Why each F row stays unchecked:

| Row | What is missing |
|---|---|
| Launch the exact freshly audited executable | Executable was started from the audited path, but no SHA-256 was taken against the build being certified, so identity is asserted by path and timestamp only |
| Verify normal Win32 initialization | Window handle and title prove a window exists; `IDECore_Shutdown` has zero callers and GDI fonts were never shown to be released, so "normal initialization" is not established |
| Editor / explorer / terminal / diagnostics / model-selection surfaces | None individually exercised; each is separately classified PARTIAL or NOT_PRESENT in the coverage matrix |
| IDE chat reaches the real local inference backend | Reaches `generateStream`; the engine produces no tokens (Deep2 D2). Not demonstrated |
| Streaming / cancellation | Not exercised at runtime |
| Clean user-requested shutdown | Never performed. The audit killed the process |
| No process/thread survives normal shutdown | Cannot be satisfied by a forced kill |

A first reading in this session that the binary "exited immediately" was a background-process
wrapper artifact. It was re-measured directly with `Start-Process`; the corrected figures are
above. Neither reading constitutes runtime certification.

---

## G. Response-coded agent / groundedness

- [x] Existing response-coded agent implementation identified
- [x] Tool-protocol execution path demonstrated previously
- [x] Real observation return path demonstrated previously
- [x] False interpretation of visible post-EOS text corrected
- [x] Groundedness classification returned to **NOT_TESTABLE_YET**
- [ ] Complete D2
- [ ] Complete D1
- [ ] Complete D3
- [ ] Run response agent after lifecycle repairs
- [ ] Independently derive expected observation facts
- [ ] Parse asserted facts from model response
- [ ] Verify observed branch equals asserted branch
- [ ] Verify observed dirty state equals asserted dirty state
- [ ] Require both protocol conformance and semantic groundedness
- [ ] Certify `RAWRXD_RESPONSE_CODED_AGENT_001`

The visible probe text cannot currently be treated as reliable model-quality evidence because
generation continues beyond control/EOS tokens while those tokens can decode to empty text.

---

## H. Remaining beyond-parity subsystem audit

- [ ] FOUNDATION fully certified
- [ ] RESPONSE_AGENT fully certified
- [ ] SESSION fully certified
- [ ] TOOL_AUTHORITY fully certified
- [ ] FILESYSTEM fully certified
- [ ] CODE_INDEX fully certified
- [ ] EDIT_ENGINE fully certified
- [ ] TERMINAL fully certified
- [ ] BUILD agent fully certified
- [ ] TEST agent fully certified
- [ ] DIAGNOSTICS fully certified
- [ ] GIT agent fully certified
- [ ] PLAN mode fully certified
- [ ] CODE mode fully certified
- [ ] DEBUG mode fully certified
- [ ] ASK mode fully certified
- [ ] ORCHESTRATION fully certified
- [ ] IDE_CHAT fully certified
- [ ] INLINE_CODE fully certified
- [ ] COMPLETION fully certified
- [ ] CONTEXT_ENGINE fully certified
- [ ] MODEL_ROUTER fully certified
- [ ] LONG_TASK fully certified
- [ ] AUTHORITY fully certified
- [ ] RECEIPTS fully certified
- [ ] `RAWRXD_BEYOND_PARITY_001=PASS`

---

## I. Final completion gate

- [ ] All required shipping source files exist
- [ ] All required source files are bound to canonical CMake targets
- [ ] No required production subtree is silently omitted
- [ ] Canonical configure completes with zero required-source drops
- [ ] Canonical production targets compile
- [ ] Canonical production targets link
- [ ] IDE launches from the freshly built artifact
- [ ] IDE shuts down cleanly without forced termination
- [ ] Deep2 D2 passes four sequential generations on one engine
- [ ] Deep2 D1 result-state invariants pass
- [ ] Deep2 D3 EOS termination passes
- [ ] Real model streaming passes
- [ ] Cancellation passes
- [ ] Session state passes
- [ ] Tool authority passes
- [ ] Filesystem tools pass
- [ ] Git tools pass
- [ ] Build/test/diagnostic feedback loop passes
- [ ] Authorized editing and rollback pass
- [ ] Ask mode is proven read-only
- [ ] Code mode performs verified work
- [ ] Debug mode reproduces, repairs, and re-verifies
- [ ] Plan mode respects mutation restrictions
- [ ] IDE chat uses the same canonical agent/runtime core
- [ ] Inline edit passes
- [ ] Completion passes
- [ ] Orchestration writer isolation passes
- [ ] Receipts are immutable and evidence-derived
- [ ] Stub/fake-success fallback count is zero on the certified lane
- [ ] Semantic groundedness passes
- [ ] `RAWRXD_IDE_CMAKE_FULL_AUDIT_001=PASS`
- [ ] `RAWRXD_BEYOND_PARITY_001=PASS`

## Current overall verdict

**`RAWRXD_IDE_CMAKE_FULL_AUDIT_001 = IN_PROGRESS`**

The audit itself has produced substantial completed evidence, but the IDE is **not yet
legitimately checkable as complete**. The major measured gaps are the 225 dropped Win32IDE
sources, 1271 unbound implementation files, unreachable CMake subtrees/targets, the silently
omitted agentic CLI surface, missing clean-shutdown proof, and the still-unrepaired Deep2
D2/D1/D3 lifecycle chain.

This keeps the status strict: **discovery/audit work that actually happened is checked;
implementation or certification that has not happened remains unchecked.** It also prevents a
"found the defect" checkbox from being mistaken for a "fixed the defect" checkbox.

---

## Evidence index

| Artifact | Contents |
|---|---|
| `00_preflight.log` | HEAD, branch, staged count, toolchain, worktree state |
| `01_cmake_roots.txt` | in-scope CMake entrypoints, `cmake_minimum_required`, shipping roots |
| `02_configure.log` | 1828 lines; 225 `WIN32IDE_SOURCES` drops; 0 errors |
| `03_targets.csv` | 132 solution projects |
| `06_ide_build.log` | 651 lines; 0 compile errors; 0 link errors; 68 warnings |
| `18_ctest_inventory.log` | `Total Tests: 0` |
| `20_dumpbin_dependents.txt` | 17 dependent DLLs |
| `20_dumpbin_headers.txt` | x64, Windows GUI, `WinMainCRTStartup` |
| `RECEIPT.md` | full audit receipt: coverage matrix, honesty findings, P0–P5 ordering |
| `build_ide_audit/` | isolated build tree; **not** the shipping build directory |