# FIVE_LAYER_AUDIT — HIDDEN_GAP_AUDIT_001

```
ASOF_UTC=2026-11-09T12:50:00Z
WORKER=W5
CONTROLLING_TIP=CC79
CONTROLLING_SHA=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
A4F_IMMUTABLE=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
STATIC_RE ≠ RUNTIME_PASS
NOT_RUN ≠ PASS
SOURCE_WIRED ≠ RUNTIME_REACHED ≠ PASS
```

This audit separates **static reverse-engineering findings** from **runtime measurements**. Static presence/wiring never upgrades to PASS.

---

## 1) Build graph

### Static RE (SOURCE_WIRED / structure)

| Feature sample | CMake / target | Translation units (authority tree) | Linked into CC79 Ext tip? |
|----------------|----------------|--------------------------------------|---------------------------|
| Terminal / ConPTY | `RawrXD-Win32IDE-Native` (+ Ext when `RAWRXD_NATIVE_IDE_EXT`) | `Win32TerminalManager.cpp/.h` listed in CMakeLists (~1519, ~3794, Ext block) | **Static:** sources in Ext target graph. **Runtime:** Terminal smoke PASS on CC79 (TERMINAL_GATE) — separate from Output HWND. |
| Debugger | same Native / Ext targets | `Win32IDE_Debugger.cpp` in CMakeLists | **Static:** linked. **Runtime:** `IDE_DEBUG_UI=FAIL` on CC79 (DEBUG_CONSOLE_GATE); headless backend PASS ≠ UI PASS. |
| Problems / diagnostics | Native UI path (addProblem / parse in Core/Commands) | No separate `Win32IDE_ProblemsPanel.cpp` in F:\ authority CMake (compare-tree `~dev\rawrxd` has extra panel TU — **do not mix trees**) | **Static:** parse + listview id 1312 present. **Runtime:** CC79 items=0 FAIL; INTEG004 sealed Problems PASS on `47451F24` only (artifact absent/drift). |
| ExtensionHost | `RAWRXD_NATIVE_IDE_EXT` → `RawrXD-Win32IDE-Native-Ext` + QuickJS | `quickjs_extension_host.cpp`, `quickjs_vscode_bindings.cpp`, tip_ext sources | **Static:** Ext target optional (OFF default). **Runtime:** CC79 EXT hello PASS; INTEG004 EXT_CLEANUP FAIL; PR79 tip NOT_BUILT. |
| Output channels | HWND ids 1604–1611 in `Win32IDE.cpp` | `SetWindowLongPtrA(hEdit, GWLP_ID, …)` staged for Build=1604 | **Static:** id remap LANDED in source. **Runtime:** tip006 still `IdLen(1604)=-1` → OUTPUT_HWND FAIL. |

### Flagged H01/H03-style risks (static)

- **H01:** Legacy targets behind `if(FALSE)` (D014) — intentional orphan risk if release docs still advertise them.
- **H04:** Ext host not in slim A4F; full-feature requires Ext tip build flag.
- **H02/H03:** `asm_stubs.cpp` (D011) and historical debugger stub (D001) need link-map / SHA reverify — **INVESTIGATE**, not CONFIRMED stubs on today’s tree without map.

### Runtime NOT_RUN / FAIL (do not conflate with static)

| Item | Runtime |
|------|---------|
| Clean-clone full CMake admission (#57 A03/A06) | NOT_RUN |
| PR75/PR77/PR78/PR79 tip EXEs | NOT_BUILT / NOT_RUN |
| Feature→symbol frozen manifest (#57 A05) | NOT_RUN |

---

## 2) Command graph

### Static RE

Sample from `Win32IDE_Commands.cpp` — handlers present for File/Edit/View/Terminal/Tools/Debug/Git/Agent families (`IDM_*` cases return into real methods: `attachDebugger`, `onAgentStartLoop`, `showGitStatus`, etc.).

**PR77 critical ID law:** on PR77 tip, `3014` = `IDM_TOOLS_GGUF_INSPECTOR`; on F:\ oneshot track, `3014` was Build Project. Cross-tip harness ID reuse is a **command-graph footgun** (H13).

### Runtime

| Check | Result |
|-------|--------|
| Enumerate + invoke every release-scope menu/toolbar/keybinding | **NOT_RUN** |
| Agent tools → durable filesystem change | **NOT_RUN** (PR78) |
| Debug UI BP/step/continue from IDE | **FAIL** on CC79 (`IDE_DEBUG_UI=FAIL`) |
| Build → Output HWND id 1604 | **FAIL** tip005/tip006 (H16 CONFIRMED) |

Static handler presence ≠ command PASS.

---

## 3) Lifecycle graph

### Ownership chains (static + measured)

| Resource | Ownership (static) | Cancel / destroy evidence | Runtime |
|----------|--------------------|---------------------------|---------|
| HWND Output 1604 | Created in panel channel defs; GWLP_ID staged | tip006 never enumerable | **FAIL** (H16) |
| HWND Problems 1312 | SysListView32 present | Items empty on CC79 when feed poisoned | **FAIL feed** (H27); HWND itself present |
| Extension host/worker | QuickJS tip_ext + ProductExtensionRuntime (PR79) | CC79: DEACTIVATE/RELOAD/ORPHANS=0; INTEG004: FORCE_KILL=1 | CC79 PASS fixture / INTEG004 **CONFIRMED cleanup FAIL** (H51) |
| ConPTY / terminal child | `Win32TerminalManager` CreatePseudoConsole | Cancel/orphan proof | Terminal smoke PASS on CC79; cancel stress **NOT_RUN** |
| AgentSession | PR78 sources | Kill/Restore | **NOT_RUN** (H57–H58 UNVERIFIED) |
| GPU / inference | Deep2 / Ollama paths | Cancel leaves GPU work | **NOT_RUN** (H75) |
| Chat stop callbacks | Inference UI marshal SOURCE_WIRED (PR77) | Stale HWND after cancel | **NOT_RUN** (H18) |

### Static vs runtime separation

- SOURCE_WIRED cancel APIs (PR78/PR79 receipts) ≠ lifecycle PASS.
- Fixture EXT lifecycle PASS on CC79 ≠ real-extension crash recovery PASS (H56).

---

## 4) Failure graph

| Dependency / op | Documented fault path? | Runtime evidence |
|-----------------|------------------------|------------------|
| Compiler under `VS_UNICODE_OUTPUT` | Yes — PROBLEMS_PANEL_GATE isolated poison/scrub | **CONFIRMED** FAIL on CC79 product Problems (H27) |
| Output HWND binding | TIP005_HWND_REPAIR / tip006 remeasure | **CONFIRMED** FAIL (H16) |
| Compiler cancel / descendant kill | Patches staged; bounded wait notes | **NOT_RUN** product cancel proof (H29/H30) |
| Model cancel / GPU teardown | Required by #49 / PR77 | **NOT_RUN** (H75) |
| Extension malformed fault | CC79 `MALFORMED_FAULT_ISOLATED=1` | Fixture only — broader **NOT_RUN** |
| CI runner empty steps | #57 A01 / PR75–76 | Infra FAIL/NOT_RUN — **not** proven false-green (H103 INVESTIGATE) |
| Agent build-failure recovery | #49 mandatory | **NOT_RUN** |

Fault-injection coverage is sparse; absence of injection ≠ PASS.

---

## 5) Acceptance graph

### Mandatory feature → test → SHA → receipt → disposition

| Mandatory axis | Test / gate | SHA scope | Receipt | Disposition |
|----------------|-------------|-----------|---------|-------------|
| Problems UI | PROBLEMS_PANEL_GATE / INTEG004 | CC79=`FAIL`; `47451F24`=`PASS` sealed | INTEG004 + PROBLEMS_PANEL_GATE | Candidate ≠ controlling; artifact drift |
| Output HWND | OUTPUT_GATE / OUTPUT_PANEL_GATE | tip005 CC79 FAIL; tip006 `5A71CA26` FAIL | oneshot gates | H16 CONFIRMED; repair continues |
| EXT lifecycle | EXTENSIONHOST_GATE / INTEG004_EXT | CC79 PASS fixture; INTEG004 FAIL cleanup | EXT receipts | H51 SHA-scoped CONFIRMED |
| Chat AIM | NATIVE_EDITOR_CHAT_GATE | CC79 PASS 7/7 | chat gate | ≠ #49 agentic chat |
| Terminal | TERMINAL_GATE | CC79 PASS smoke | terminal gate | ≠ cancel/stress PASS |
| Debug UI | DEBUG_CONSOLE_GATE | CC79 IDE UI FAIL; headless PASS | debug gate | Four-panel hold |
| Four-panel | FOUR_PANEL_INTEGRATION | CC79 OPEN | four-panel | NOT_DEMONSTRATED |
| Finish-25 | FINISH_25_BACKLOG / oneshot matrix | Historical 19/25; current 4/25 | Finish-25 ledgers | Do not arithmetically mix |
| Issue #49 product-final | ISSUE49_PRODUCT_FINAL_GATE_MAP | no SHA | #49 OPEN | All scenario steps NOT_RUN / FAIL conjunction |
| PR77–79 | PR7*_ACCEPTANCE_001 | tips NOT_BUILT | MERGE_READY=0 | CONFLICTING ≠ impl CONFIRMED |

### Issue #49 mapping (acceptance)

Every #49 receipt key remains **OPEN / NOT_PROVEN** on both CC79 and INTEG004 (see `FULL_FEATURE_FINAL_COMPLETION_001\HIDDEN_GAP_AUDIT_001\ISSUE49_PRODUCT_FINAL_GATE_MAP.md`). Subsystem seals do not satisfy product-final.

---

## Static RE vs runtime — summary table

| Layer | Static finding | Runtime |
|-------|----------------|---------|
| Build | Terminal/Debugger/Ext TUs in CMake Ext graph; Problems panel TU differs across trees | Clean rebuild / PR tips NOT_RUN; A4F slim ≠ Ext |
| Command | Broad `IDM_*` handlers wired | Full invoke matrix NOT_RUN; Output/Debug FAIL axes |
| Lifecycle | GWLP_ID 1604 staged; Ext deactivate APIs present | 1604 unbound on tip006; INTEG004 EXT cleanup FAIL |
| Failure | VS_UNICODE root cause documented | CC79 Problems CONFIRMED FAIL |
| Acceptance | Inventories (#49/#50/#57, H01–H120, Finish-25) large | MAJOR_INTEGRATED_ACCEPTANCE=**NOT_DEMONSTRATED** |

```
STATIC_RE_COMPLETE_SAMPLE=1
RUNTIME_PRODUCT_PASS=0
FIVE_CROSS_SUBSYSTEM_CONJUNCTION=NOT_ON_ANY_SINGLE_SHA
MASTER_CONFIRMED=8
W5_FAIL_CLOSED_RECONCILE=1
CONTROLLING_TIP=CC79
PROMOTE=0
```

See `MASTER_HIDDEN_GAP_REGISTER.md` for full H01–H120 statuses after sibling merge + W5 demotions.
