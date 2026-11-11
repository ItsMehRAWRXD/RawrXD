# REQUIREMENT_DEDUPE_MATRIX — HIDDEN_GAP_AUDIT_001

```
ASOF_UTC=2026-11-09T12:45:00Z
ENGINEERING_MATURITY_ESTIMATE=82%
ESTIMATE_CHANGE=0
CONTROLLING_TIP=CC79
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
TIP_MOVE_AUTHORIZED=0
A4F_IMMUTABLE=1
DOUBLE_COUNT=0
INVENT_CONFIRMED_DEFECT=0
CROSS_SHA_PASS_INHERITANCE=0
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
H_SOURCE=HIDDEN_GAP_AUDIT_001\_extract_hcat.txt (owner complete register)
78_REGISTER=ABSENT_LOCALLY
```

## Deduplication law

```
H01–H120 = investigation targets (not 120 defects)
Issue#57_45 + Finish25_25 + Issue#49_keys + PR75–79 ≠ arithmetic sum of acceptance work
DUPLICATE_OF marks same underlying requirement
78+120+45 ≠ ACCEPTANCE_COUNT
SEARCH_MISS ≠ ABSENCE (see GITHUB_INDEX_NOTE.md)
```

### Corpus inventory (reconcile, do not sum)

| Corpus | Count / state | Location |
|--------|---------------|----------|
| H01–H120 | 120 INVESTIGATE targets | owner extract `_extract_hcat.txt` |
| Finish-25 historical | 19/25; remaining T05,T07,T08,T18,T19,T25 | `POST_E59D_CANDIDATE_001\FINISH_25_BACKLOG.md` |
| Finish-25 CURRENT CC79 | 4/25 | `FULL_FEATURE_FINAL_COMPLETION_001\FINISH25_MATRIX.md` |
| Finish-25 CURRENT oneshot | 4/25 | `FULL_FEATURE_ONESHOT_001\FINISH25_MATRIX.md` |
| DAILY_DRIVER GATE_BOARD | Slim PASS; full-feature FAIL | `DAILY_DRIVER_CLOSE_001\GATE_BOARD.md` |
| Issue #49 | Product-final E2E + receipt keys OPEN | gh issue 49 |
| Issue #50 | Ladder 0–10 OPEN/blocked | gh issue 50 |
| Issue #57 | 45 gates unchecked | gh issue 57 |
| PRs #75–#79 | Unmerged acceptance inventory | gh pr + `GITHUB_PR_ISSUE_INVENTORY.md` |
| INTEG_004 | Problems PASS candidate; EXT_CLEANUP FAIL | local FINAL_COMPLETION receipts |
| ~78-item register | **ABSENT_LOCALLY** | mentions only |

---

## Section map — H-ID ↔ external corpora

Status values: `CONFIRMED` | `UNVERIFIED` | `INVESTIGATE` | `OUT_OF_SCOPE` | `DUPLICATE_OF:<ref>`

### 1. Source / build integrity (H01–H12)

| ID | Gap (short) | Status | Dedupe / maps |
|----|-------------|--------|---------------|
| H01 | Source excluded from prod CMake | UNVERIFIED | #57 A03/A05 · #46 Layer-7 · #49 STRICT_BUILD |
| H02 | Duplicate impl; older linked | INVESTIGATE | #57 A05 feature→symbol |
| H03 | Stub replaces production | UNVERIFIED | #49 STUB_*=0 · PR77–79 non-claims |
| H04 | Feature flags disable release comps | INVESTIGATE | CMake/release audit |
| H05 | Missing deps hidden by incr builds | UNVERIFIED | #57 A02/A06 clean checkout |
| H06 | Stale objects false-success | INVESTIGATE | clean rebuild |
| H07 | Debug≠Release behavior | INVESTIGATE | — |
| H08 | Bad defs / inherited env | **CONFIRMED** axis via C1 (`VS_UNICODE_OUTPUT` / env) on CC79 | DUPLICATE_OF:C1 · H27 |
| H09 | Unresolved symbols optional paths | UNVERIFIED | #49 UNRESOLVED_EXTERNALS=0 |
| H10 | Branch incompatible impls | INVESTIGATE | PR #76 divergence |
| H11 | Generated assets missing clean | UNVERIFIED | #57 A02/#49 CLEAN_CLONE |
| H12 | Non-reproducible binaries | UNVERIFIED | #49 CI/CLEAN_MACHINE_REPRO · #57 A01 |

### 2. Win32 GUI / events (H13–H26)

| ID | Gap (short) | Status | Dedupe / maps |
|----|-------------|--------|---------------|
| H13 | Menu → wrong/missing handler | INVESTIGATE | command graph RE |
| H14 | Toolbar no-op | INVESTIGATE | — |
| H15 | Shortcuts bypass path | INVESTIGATE | Finish25 chat/key axes |
| H16 | HWND after destroy | INVESTIGATE | PR #78 stale-HWND · C3 Debug UI |
| H17 | Worker touches UI directly | INVESTIGATE | PR #77 async marshal |
| H18 | Posted msgs after cancel | INVESTIGATE | PR #78 cancel |
| H19 | Reentrant WndProc | INVESTIGATE | — |
| H20 | Focus breaks keyboard | INVESTIGATE | Chat/panel focus |
| H21 | DPI / geometry | INVESTIGATE | — |
| H22 | Resize destroys controls | INVESTIGATE | four-panel |
| H23 | Modal blocks background | INVESTIGATE | — |
| H24 | UI deadlock on compile/model | INVESTIGATE | H28 pipes |
| H25 | Exception in dispatch | INVESTIGATE | — |
| H26 | Recreation loses state | UNVERIFIED | Finish25 T10 restore · #57 A08 |

### 3. Compiler / linker / Problems (H27–H42)

| ID | Gap (short) | Status | Dedupe / maps |
|----|-------------|--------|---------------|
| H27 | Compiler inherits bad env | **CONFIRMED** on CC79 (C1); candidate fix on `47451F24…` (K1) | DUPLICATE_OF:C1 · INTEG_004 · PR #77 Problems |
| H28 | Pipe backpressure deadlock | **CONFIRMED** axis on CC79 (C1) | DUPLICATE_OF:C1 |
| H29 | Child survives cancel | INVESTIGATE | Finish25 T05 · #57 A09 |
| H30 | Timeout kills parent only | INVESTIGATE | T05 |
| H31 | Paths-with-spaces parse | INVESTIGATE | Problems parse |
| H32 | Unicode diagnostics corrupted | **CONFIRMED** axis on CC79 (C1); scrub PASS candidate K1 | DUPLICATE_OF:C1 |
| H33 | Warnings as errors | INVESTIGATE | — |
| H34 | Duplicate Problems entries | INVESTIGATE | — |
| H35 | Stale diagnostics after rebuild | INVESTIGATE | — |
| H36 | Click-to-line no navigation | UNVERIFIED on CC79; PASS candidate on `47451F24…` | K1 · PR #77 |
| H37 | Bad line/col offsets | INVESTIGATE | — |
| H38 | Multi-project ownership mix | INVESTIGATE | — |
| H39 | Linker errors missing | INVESTIGATE | PR #75 |
| H40 | Failed build reports success | INVESTIGATE | H65 agent |
| H41 | PE/COFF linker accepts bad reloc | UNVERIFIED | PR #75 16 unexecuted · #57 B11 |
| H42 | Adapter PASS ≠ native complete | UNVERIFIED | PR #75 37 local vs 16 unexecuted |

### 4. ExtensionHost / IPC (H43–H56)

| ID | Gap (short) | Status | Dedupe / maps |
|----|-------------|--------|---------------|
| H43 | Discovery without activation | INVESTIGATE | PR #79 · Finish25 T16 |
| H44 | Worker without IPC handshake | UNVERIFIED | PR #79 |
| H45 | IPC framing/size | INVESTIGATE | PR #79 |
| H46 | Ext cmd wrong thread | INVESTIGATE | — |
| H47 | Protocol version skew | INVESTIGATE | — |
| H48 | Ext crash kills IDE | INVESTIGATE | PR #79 crash recovery |
| H49 | Unload leaves callbacks | INVESTIGATE | — |
| H50 | Reload duplicates cmds | INVESTIGATE | EXT reload axis |
| H51 | Ext process survives IDE shutdown | **CONFIRMED** on `47451F24…` (C2 EXT_CLEANUP/FORCE_KILL) | DUPLICATE_OF:C2 · PR #79 · T16 |
| H52 | Crashed worker restart | UNVERIFIED | PR #79 |
| H53 | FS bypass permissions | INVESTIGATE | H91 |
| H54 | Handlers block UI | INVESTIGATE | — |
| H55 | State corrupt across projects | INVESTIGATE | — |
| H56 | Test ext PASS; real FAIL | INVESTIGATE | PR #79 real extension |

### 5. AgentSession / autonomous coding (H57–H72)

| ID | Gap (short) | Status | Dedupe / maps |
|----|-------------|--------|---------------|
| H57 | Session ownership missing | UNVERIFIED | PR #78 · #50 L3 |
| H58 | Cancelled agent continues | UNVERIFIED | PR #78 · Finish25 T05 |
| H59 | Stale tool results injected | INVESTIGATE | #49 RESULT_REINJECTION |
| H60 | Tool call parse wrong | INVESTIGATE | #49 REAL_TOOL_CALL |
| H61 | Permission bypass | INVESTIGATE | #49 TOOL_AUTHORITY · H92 |
| H62 | Wrong workspace/file edit | INVESTIGATE | #49 REAL_SOURCE_EDIT |
| H63 | Partial write corrupt | INVESTIGATE | — |
| H64 | No rollback | UNVERIFIED | #57 A15 · #50 L4 |
| H65 | Reports build success w/o evidence | UNVERIFIED | #49 FINAL_BUILD |
| H66 | Infinite failure loop | INVESTIGATE | — |
| H67 | Tool blocks streaming | INVESTIGATE | PR #77 inference UI |
| H68 | Concurrent agents overwrite | UNVERIFIED | #50 L5 multi-agent |
| H69 | No recover after restart | UNVERIFIED | Finish25 T10 |
| H70 | Reviewer approves untested | UNVERIFIED | #49 MULTI_AGENT_REVIEW |
| H71 | Git commit unrelated mods | INVESTIGATE | #49 IDE_GIT |
| H72 | Reports done before tests | UNVERIFIED | #49 FINAL_TESTS · H120 |

### 6. Local inference / Deep2 (H73–H90)

| ID | Gap (short) | Status | Dedupe / maps |
|----|-------------|--------|---------------|
| H73 | Wrong model/backend | UNVERIFIED | #49 LOCAL_MODEL_LOAD |
| H74 | Ollama stream JSON frag | INVESTIGATE | — |
| H75 | Cancel leaves GPU work | INVESTIGATE | Finish25 T05 |
| H76 | Shutdown leaks | INVESTIGATE | — |
| H77 | Load OK; invalid output | UNVERIFIED | #49 GENERATION/FINITE_LOGITS |
| H78 | Offload counters ≠ reality | UNVERIFIED | #57 C · #50 L2 |
| H79 | Quant kernels wrong | UNVERIFIED | #57 C03 |
| H80 | KV rollback corrupt | INVESTIGATE | — |
| H81 | Long-context OOM | INVESTIGATE | — |
| H82 | Multi-GPU bad placement | UNVERIFIED | #57 C08 · #50 L5 |
| H83 | Sync serializes parallel | INVESTIGATE | #57 C09 |
| H84 | Silent CPU fallback | UNVERIFIED | #50 L2 CPU_FALLBACK=0 |
| H85 | Driver vs model misattr | INVESTIGATE | — |
| H86 | Switch retains stale tok/samp | INVESTIGATE | — |
| H87 | Device loss needs IDE restart | INVESTIGATE | — |
| H88 | Benchmark excludes waits | UNVERIFIED | #57 C12/#50 L9 |
| H89 | Corrupt GGUF accepted | UNVERIFIED | #57 C10 |
| H90 | Local path needs external net | UNVERIFIED | #49 clean/offline |

### 7. Security / release integrity (H91–H106)

| ID | Gap (short) | Status | Dedupe / maps |
|----|-------------|--------|---------------|
| H91 | Path traversal tools | INVESTIGATE | — |
| H92 | Model bypasses auth | UNVERIFIED | #49 TOOL_AUTHORITY |
| H93 | Shell arg injection | INVESTIGATE | — |
| H94 | Secrets in logs | INVESTIGATE | — |
| H95 | Unauthorized IPC cmds | INVESTIGATE | PR #79 |
| H96 | Ext validation weak | INVESTIGATE | — |
| H97 | Placeholder crypto | INVESTIGATE | — |
| H98 | Undeclared DLL deps | UNVERIFIED | packaging T24 |
| H99 | Installer out of dir | UNVERIFIED | Finish25 T24 |
| H100 | Uninstall destroys data | INVESTIGATE | — |
| H101 | Crash recovery unsafe replay | INVESTIGATE | — |
| H102 | Receipts without provenance | UNVERIFIED | #49 SYNTHETIC_RECEIPTS=0 · H106 |
| H103 | GHA success without tests | UNVERIFIED | #57 A01 · PR #75/#76 CI |
| H104 | LFS/branch incomplete source | INVESTIGATE | PR #76 |
| H105 | Signed ≠ tested exe | UNVERIFIED | #57 C15 · Finish25 T25 |
| H106 | Cert from multiple SHAs | UNVERIFIED | NO_CROSS_SHA law · C1/K1 |

### 8. Additional product-completion (H107–H120)

| ID | Gap (short) | Status | Dedupe / maps |
|----|-------------|--------|---------------|
| H107 | LSP handshake without real diag/comp | UNVERIFIED | #57 A11 · #50 L6 |
| H108 | GhostText wrong range | UNVERIFIED | #57 A12 |
| H109 | Browser lacks isolation | UNVERIFIED | #57 A13 |
| H110 | Git wrong repo/branch | INVESTIGATE | #49 IDE_GIT |
| H111 | Snapshot restore fails | UNVERIFIED | #57 A15 |
| H112 | Settings not applied | INVESTIGATE | — |
| H113 | Registry advertises dead cmds | INVESTIGATE | H03/H13 |
| H114 | Cross-platform claimed w/o native run | **OUT_OF_SCOPE** (Mach-O/Android/ELF hosts) unless #49 scope expands | DUPLICATE_OF:#57 B13–B15 OUT_OF_SCOPE |
| H115 | Synthetic kernel perf | UNVERIFIED | #57 C12 · #50 L9 |
| H116 | Docs claim absent capability | INVESTIGATE | — |
| H117 | Tests omit negative/recovery | UNVERIFIED | acceptance graph |
| H118 | Components fail when simultaneous | **UNVERIFIED** / aligns C4 four-panel OPEN | DUPLICATE_OF:C4 · PR #77 |
| H119 | Fixtures hide env deps | INVESTIGATE | C1 fixture axis |
| H120 | Final acceptance omits full autonomous loop | **UNVERIFIED** mandatory | DUPLICATE_OF:#49 · #50 L10 · Finish25 T25 |

---

## Crosswalk — external IDs → H / Finish25 / defects

| External | Primary overlap | Status note |
|----------|-----------------|-------------|
| Issue #49 full scenario | H120, H57–H72, H73–H90, Finish25 T25 | UNVERIFIED decisive milestone |
| Issue #50 L0–L10 | H73–H90, H57–H72, H120 | Ladder OPEN; no layer PASS invented |
| Issue #57 A01–A15 | H01–H12, H107–H113, H26, terminal/debug | UNVERIFIED in-scope |
| Issue #57 B01–B12 | H41–H42, PR #75 | UNVERIFIED (compiler track) |
| Issue #57 B13–B15 | H114 | **OUT_OF_SCOPE** daily-driver Win32 |
| Issue #57 C01–C15 | H78–H89, H115, #50 L2/L9 | UNVERIFIED GPU/release |
| PR #77 | H27–H40, H118, Finish25 T17/Problems/Output | OPEN CONFLICTING inventory |
| PR #78 | H16–H18, H57–H58 | OPEN CONFLICTING inventory |
| PR #79 | H43–H56, **H51=C2** | OPEN CONFLICTING; cleanup CONFIRMED on integ SHA |
| PR #75 | H41–H42 | 16 linker tests UNEXECUTED |
| PR #76 | H10, H104 | HELD consolidation |
| Finish25 T05 | H29–H30, H58, H75 | Historical remaining / UNVERIFIED on controlling arithmetic |
| Finish25 T07/T08 | editor Unicode/tab | Historical remaining |
| Finish25 T16 | H43–H56, C2 | CURRENT PASS on CC79 ≠ integ cleanup |
| Finish25 T17 | terminal | CURRENT PASS CC79; NEEDS_REVERIFY integ |
| Finish25 T18/T19 | endurance | Historical remaining |
| Finish25 T20 | chat | CURRENT PASS CC79; NEEDS_REVERIFY integ |
| Finish25 T21–T23 | debug | C3 UI FAIL on CC79 |
| Finish25 T24/T25 | package/cert | T24 partial; T25 CERTIFIED=0 · H120 |
| INTEG_004 Problems PASS | H27/H28/H32/H36 | Candidate K1 only |
| INTEG_004 EXT_CLEANUP FAIL | H51 | CONFIRMED C2 |
| CC79 Problems items=0 | H27/H28/H32 | CONFIRMED C1 |
| DAILY_DRIVER A4F | slim subset of Finish25 | SLIM≠FULL; EXT OOS |
| 78-register | — | ABSENT_LOCALLY — no rows to dedupe |

---

## Double-count prevention board

| If you are about to count… | Count once as… | Do not also add… |
|----------------------------|----------------|------------------|
| VS_UNICODE / empty Problems on CC79 | **C1** | separate H27+H28+H32 defects |
| EXT FORCE_KILL cleanup | **C2** | separate H51 + PR #79 + T16 fails |
| Debug UI E2E FAIL | **C3** | Finish25 T21–T23 as extra CONFIRMED |
| Four-panel OPEN | **C4** / H118 | PR #77 four-panel as second CONFIRMED |
| Issue #49 loop | **H120** / #49 | + Finish25 T25 + #50 L10 as three CONFIRMED |
| #57 B14/B15 | OUT_OF_SCOPE | mandatory daily-driver blockers |
| 45+#49+25+120 | inventory only | maturity % or PASS count |

```
DEDUPE_MATRIX=SEALED
DOUBLE_COUNT=0
CONFIRMED_ONLY_VIA_MASTER_DEFECT_REGISTER=1
NEXT=NEXT_EXECUTABLE_GATES.md
PROMOTE=0
ENGINEERING_MATURITY_ESTIMATE=82%
ESTIMATE_CHANGE=0
```
