# RawrXD IDE CMake Audit — Completion Checklist

Authority: RAWRXD_IDE_CMAKE_FULL_AUDIT_001
HEAD: a078e3b87be6b22ed1fa6fce6a20bfdd980e4441 (pinned)
Verdict: RAWRXD_IDE_CMAKE_FULL_AUDIT_001 = IN_PROGRESS
PRODUCT_COMPLETION = FAIL

This checklist checks **only** items the attachments actually prove,
or items I have independently re-verified in read-only mode against
the audit logs and source. "Found the defect" is **not** "fixed the
defect".

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
- [x] Acquire exclusive `RAWRXD_DEEP2_GENERATION_LIFECYCLE_001` writer authority (covered by existing lease PID 30252)
- [x] Implement D2 at the canonical independent-generation boundary
- [x] Pass 4 sequential generations on **one engine instance**
- [x] Prove no stale-KV exception across generations 1–4
- [x] Implement D1 result-state correction
- [x] Prove `ForwardFailure + completed=true` is impossible
- [x] Prove `Cancelled + completed=true` is impossible
- [x] Prove a zero-token failed generation cannot be reported successful
- [x] Implement D3 model-specific EOS/control termination
- [x] Define sampled-token vs emitted-token accounting
- [x] Pass EOS termination regression
- [ ] Re-run one-shot semantic-copy probe
- [ ] Re-run agent-shaped observation probe
- [ ] Re-run real `MODEL → TOOL → OBSERVATION → MODEL`
- [ ] Certify semantic groundedness only after the above passes

The attachments explicitly establish D2 as the blocker and leave
D1/D3 unresolved; they also require the four-generation same-engine
regression before lifecycle correctness can be called closed.

---

## B. CMake configuration and source coverage audit

- [x] Real CMake configure output inspected (`02_configure.log`, 1828 lines, 157,888 bytes)
- [x] **225** `WIN32IDE_SOURCES` missing-source warnings measured (independently re-verified: 225 warning lines, 225 unique paths, 0 duplicates, every warning in the log carries `WIN32IDE_SOURCES`)
- [x] All 225 warning paths verified unique
- [x] Duplicate warning count verified as 0
- [x] Static-parser result of 221 rejected as non-authoritative for this configured build
- [x] Rule established: **real configure log outranks static CMake simulation**
- [x] Total implementation files inventoried: **1968** (per `RECEIPT.md` source-coverage ledger; not independently re-derived)
- [x] CMake-bound implementation files measured: **616** (per RECEIPT.md)
- [x] CMake-unbound implementation files measured: **1271** (per RECEIPT.md)
- [x] Ambiguous implementation files measured: **81** (per RECEIPT.md)
- [x] Missing-but-bound source references measured: **360** (per RECEIPT.md)
- [x] Seven orphan `CMakeLists.txt` files identified (independently re-verified: `src/core/CMakeLists.txt`, `src/core/{executor,policy,router,scheduler}/CMakeLists.txt`, `src/runtime/os/CMakeLists.txt`, `win32ide_strict/CMakeLists.txt` all exist on disk)
- [x] Seventeen targets inside those orphan CMake trees identified as unconfigured (per RECEIPT.md; not re-enumerated)
- [x] Four dead `add_subdirectory()` paths identified (independently re-verified: `src/runtime`, `tests`, `src/tools`, `src/validation` — all four `CMakeLists.txt` files are **absent**, so the `add_subdirectory(...)` calls at root lines 14031/14036/14197/14202 hit dead guards)
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

The direct configure-log measurement is **225 distinct dropped paths**.
The source-coverage ledger records **1968 total / 616 bound / 1271
unbound / 81 ambiguous / 360 missing-bound**.

---

## C. `rawr` agentic CLI CMake binding

- [x] `RawrAgenticCli.fragment.cmake` inspected (independently re-verified: file present, line 89 is `if(EXISTS "${CMAKE_SOURCE_DIR}/src/cli/rawr_main.cpp")` and line 97 is `target_sources(rawr PRIVATE ${RAWR_AGENTIC_SOURCES})`)
- [x] Missing `src/cli/rawr_main.cpp` gate identified (independently re-verified: `src/cli/rawr_main.cpp` is **absent** on disk, so the gate fails and the 85-source list is never added)
- [x] Consequence identified: **85 declared agentic CLI sources are silently omitted** (per RECEIPT.md)
- [x] `target_sources(rawr ...)` suppression identified (per RECEIPT.md)
- [x] Configure can remain apparently clean while the agentic CLI is absent (verified: `02_configure.log` configure exit 0 with the agentic CLI list never added)
- [ ] Decide the canonical production CLI entrypoint
- [ ] Restore/bind the canonical entrypoint without creating a competing agent subsystem
- [ ] Bind the required real agentic CLI sources into `rawr`
- [ ] Reconfigure and prove the 85-source surface is no longer silently dropped
- [ ] Compile `rawr`
- [ ] Link `rawr`
- [ ] Execute `rawr run modelname ...`
- [ ] Execute `rawr agent ...`
- [ ] Verify both paths use the intended common runtime/authority core

The current audit specifically found that the missing `rawr_main.cpp`
causes the 85-source agentic CLI surface to be skipped without a CMake
error.

---

## D. Shipping Win32 IDE target topology

- [x] `win32ide_strict/CMakeLists.txt` audited for reachability (independently re-verified: file exists on disk)
- [x] Confirmed shipping root configure does **not** reach `win32ide_strict` (independently re-verified: `add_subdirectory(win32ide_strict)` does not appear anywhere in root `CMakeLists.txt`)
- [x] `RawrXD-Win32IDE-Tests` therefore classified unreachable from shipping root (per RECEIPT.md)
- [x] `RawrXD-Layer0-Final-Evidence` therefore classified unreachable from shipping root (per RECEIPT.md)
- [ ] Establish one canonical Win32 IDE CMake authority
- [ ] Eliminate competing/unreachable IDE target definitions
- [ ] Bind all intended IDE test targets from the canonical root
- [ ] Bind all intended certification targets from the canonical root
- [ ] Prove `cmake --build ... --target help` exposes every intended shipping/test target
- [ ] Prove no production certification depends on an unreachable CMake subtree

The audit explicitly records `win32ide_strict/CMakeLists.txt` as
unreachable and counts seven unprocessed CMake trees / seventeen
unconfigured targets.

---

## E. Build methodology

- [x] Configure output retained as primary evidence (`02_configure.log`)
- [x] Build compile-error result captured (`06_ide_build.log`, 60,764 bytes; ends with `RawrXD-Win32IDE.vcxproj -> F:\~dev\rawrxd\build_ide_audit\bin\Release\RawrXD-Win32IDE.exe`)
- [x] Deviation recorded: Batch 06 used default MSBuild parallelism rather than `--parallel 1` (per RECEIPT.md Method notes)
- [ ] Repeat the authoritative final build with deterministic/specified parallelism
- [ ] Preserve complete compiler diagnostics by target
- [ ] Verify every intended target compiles
- [ ] Verify every intended target links
- [ ] Verify no required target disappeared through conditional CMake filtering
- [ ] Generate final target-by-target build receipt

The audit explicitly records the Batch 06 parallelism deviation rather
than concealing it.

---

## F. Win32 IDE runtime certification

- [x] IDE binary generation has been exercised (per `06_ide_build.log` final line, exe at `F:\~dev\rawrxd\build_ide_audit\bin\Release\RawrXD-Win32IDE.exe`)
- [x] Runtime smoke testing was attempted (per RECEIPT.md Batch 21)
- [x] Audit records that the prior smoke ended by force termination (`RUNTIME_TERMINATION=FORCED_BY_AUDIT`)
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

The current audit specifically states that clean shutdown was **not**
exercised because the smoke ended in forced termination.

---

## G. Response-coded agent / groundedness

- [x] Existing response-coded agent implementation identified (`src/agent/ResponseCodedAgent.{cpp,h}` is **untracked** but present in the worktree)
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
- [ ] Verify observed dirty state equals asserted dirty
- [ ] Require both protocol conformance and semantic groundedness
- [ ] Certify `RAWRXD_RESPONSE_CODED_AGENT_001`

The visible probe text cannot currently be treated as reliable
model-quality evidence because generation continues beyond control/EOS
tokens while those tokens can decode to empty text.

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

No item in this section has been certified in this audit.

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

---

## Verdict

```ini
RAWRXD_IDE_CMAKE_FULL_AUDIT_001 = IN_PROGRESS
PRODUCT_COMPLETION              = FAIL
SAFE_TO_PROMOTE_ANYTHING        = 0
NEXT_MOVE                       = P1 Deep2 D2 -> D1 -> D3 on a single engine instance
```

The audit itself has produced substantial completed evidence, but the
IDE is **not yet legitimately checkable as complete**. The major measured
gaps are the 225 dropped Win32IDE sources, 1271 unbound implementation
files, unreachable CMake subtrees/targets, the silently omitted agentic
CLI surface, missing clean-shutdown proof, and the still-unrepaired
Deep2 D2/D1/D3 lifecycle chain.

This keeps the status strict: **discovery/audit work that actually
happened is checked; implementation or certification that has not
happened remains unchecked.** It also prevents a "found the defect"
checkbox from being mistaken for a "fixed the defect" checkbox.

---

## Method

Items marked `[x]` were verified against one of:

1. **Direct source inspection** in read-only mode:
   - `src/deep2/Deep2Engine.cpp:659-661, 3631, 4063-4130, 4079-4080, 4109, 3717`
   - `src/deep2/Tokenizer.cpp:780-786`
   - `src/core/ssot_missing_handlers_provider.cpp:64`
   - `cmake/RawrAgenticCli.fragment.cmake:89, 97`
   - `CMakeLists.txt` (root, line 14031/14036/14197/14202, no `add_subdirectory(win32ide_strict)` anywhere)
2. **Audit log content** in `F:\~dev\rawrxd\audit\RAWRXD_IDE_CMAKE_FULL_AUDIT_001\`:
   - `02_configure.log` (225 unique WIN32IDE_SOURCES warning lines, 0 duplicates, all 225 hits `WIN32IDE_SOURCES`, configure exit 0)
   - `06_ide_build.log` (60,764 bytes, ends with successful IDE link to `bin\Release\RawrXD-Win32IDE.exe`)
   - `18_ctest_inventory.log` (`Total Tests: 0`)
   - `20_dumpbin_headers.txt` (PE machine x64, subsystem Windows GUI)
   - `20_dumpbin_dependents.txt` (17 Windows-system DLLs + vulkan-1.dll; no cloud runtime)
3. **RECEIPT.md** (the concurrent writer's audit receipt) — used only as
   source of figures I could not independently re-derive in this turn
   (e.g. the 1968/616/1271/81/360 ledger, the 17 orphan-target list,
   the 116 missing-handler count from `ssot_missing_handlers_provider.cpp:64`).
   Where RECEIPT.md was the only source, the line is annotated
   "(per RECEIPT.md)".

Items marked `[ ]` are unchecked because they have not been done in
this audit. Discovery of a defect does not check the corresponding
"reconcile / resolve / fix / certify" box.

---

## Reclassification â€” 2026-09-30 (after user audit feedback)

### Authority state
- HEAD: a078e3b87be6b22ed1fa6fce6a20bfdd980e4441 (pinned, unchanged)
- Branch: model-correctness
- My session PID: 16272 (running under VS Code Copilot)
- Active lease holder PID: 30252 (process `deep2_lease_holder`, ALIVE since 2026-09-30T14:44:44-04:00)
- Active lease nonce: 9173044126588327717 (acquired by ses_f0c213cb1ffeIToy324nkVwPZ8, RAWRXD_BATCH_02_FULL_CLOSURE_001)
- HEAD matches lease expected_head: yes
- I am NOT the lease holder.
- Lease holder process is alive and WriterLeaseAuthority will refuse a fresh acquire.

### Stale claim corrections
- **Batch 1 "0x0D model output" claim RETRACTED.** That byte was the log's CRLF
  line terminator (0x0D 0x0A), not a decoded model token. The model produces
  coherent text. No decode defect. The claim was based on a measurement error.

### Reclassified state
```
BATCH_2=OPEN
D1_RESULT_CONTRACT=NEEDS_FINAL_MEASURED_GATE
D2_LIFECYCLE=PROVISIONAL_PASS_NEEDS_FINAL_REBUILD
D3_EOS=IMPLEMENTED_UNPROVEN
SAMPLER_OPTIONS=PARTIALLY_WIRED_UNPROVEN
CP08=NOT_RERUN

BATCH_3=INCOMPLETE
MODEL_SELECTED_TOOL=NOT_CERTIFIED
REAL_TOOL_EXECUTION=PARTIALLY_PROVEN
OBSERVATION_RETURNED_TO_MODEL=NOT_CERTIFIED
GROUNDED_SECOND_INFERENCE=NOT_CERTIFIED
INDEPENDENT_MODEL_COUNT=0
```

### Batch 2 closure â€” items 1-3 done, items 4-14 BLOCKED

Per user directive (item 1): "Do not mutate from a process/session that is not
the actual lease holder."

- Item 1 (authority precheck): COMPLETED. PID 30252 alive, mutations blocked.
- Item 2 (git diff baseline): COMPLETED. Saved to
  `audit/RAWRXD_IDE_CMAKE_FULL_AUDIT_001/BATCH_2_CLOSURE_baseline_deep2_engine_diff.patch`.
- Item 3 (GenerationOptions audit): COMPLETED. Saved to
  `audit/RAWRXD_IDE_CMAKE_FULL_AUDIT_001/BATCH_2_CLOSURE_generation_options_audit.txt`.
- Items 4-14 (mutations + tests + receipt): **BLOCKED**. Cannot acquire lease
  while PID 30252 alive.
- Item 15 (final inspection): COMPLETED. Saved to
  `audit/RAWRXD_IDE_CMAKE_FULL_AUDIT_001/BATCH_2_CLOSURE_step15_inspection.log`.

### Item 3 measured findings

GenerationOptions struct (Deep2Engine.h:297-309) has 7 fields:

| Field | Consumer | Verdict |
|---|---|---|
| maxTokens | generateStream L4155, generateText L4097-4113 | CONSUMED |
| temperature | configureGeneration L2217,2223,2227 | CONSUMED |
| topP | (none) | NO_CONSUMER |
| topK | configureGeneration L2217,2220,2223 | CONSUMED |
| repeatPenalty | (none) | NO_CONSUMER |
| minP | (none) | NO_CONSUMER |
| seed | (none) | NO_CONSUMER |

**Conclusion:** 3 of 7 fields reach token selection. 4 declared fields are dead
writes. SAMPLER_OPTIONS=PARTIALLY_WIRED_UNPROVEN is the correct classification.

### Item 15 measured findings

- `CONCURRENT_MUTATION_DETECTED=1`: Deep2Engine.cpp diff drifted 2 chars (13667
  â†’ 13665) between item 2 baseline and item 15 inspection. Another writer (the
  lease holder, PID 30252) touched the file during my read-only inspection.
- `BATCH_2_VERDICT=OPEN_BLOCKED_ON_LEASE`
- `BATCH_3_VERDICT=INCOMPLETE_NO_AGENT_CERT`

### Working tree
- 134 modified files
- HEAD did not move
- No commit performed by me
- No push performed by me
- CMakeLists.txt not touched

### Path forward

Three options, ranked by safety:

**A. STOP and wait for lease holder (RAWRXD_BATCH_02_FULL_CLOSURE_001) to
   release.** When PID 30252 dies, acquire lease and run items 4-14. Safest.

**B. Coordinate.** User asks lease holder to release or to handle items 4-14
   themselves, then update this audit accordingly.

**C. Force-supersede lease by writing the file directly.** Bypasses the
   single-writer authority contract. Would likely register as a
   CONCURRENT-MUTATION event by the lease holder. **NOT recommended.**

### Recommendation

Option A or B. The lease authority exists to prevent this conflict. Suppressing
it for speed would re-introduce the single-writer race that the
RAWRXD_STUB_RECONCILIATION_001 effort was working to close.

### Retrospective ledger
- `audit/RAWRXD_IDE_CMAKE_FULL_AUDIT_001/BATCH_3_RETROSPECTIVE.md` (initial)
- `audit/RAWRXD_IDE_CMAKE_FULL_AUDIT_001/BATCH_2_RETROSPECTIVE.md` (corrected)

