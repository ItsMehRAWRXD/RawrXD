# FIVE_LAYER_SOURCE_AUDIT_001 — CC79 static + receipt reconcile

```
ASOF_UTC=2026-11-09T12:40:00Z
MOTD_ACK=1
CONTROLLING_TIP=CC79
TIP_LABEL=tip_final_integ_002
TIP_EXE=candidates\tip_final_integ_002\RawrXD-Win32IDE-Native-Ext.exe
TIP_SHA256=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
TIP_SHA_DISK_VERIFY=MATCH (Get-FileHash this turn)
A4F_UNTOUCHED=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
TIP_CLIMB=HOLD
NO_TIP_003_004_PROMOTE=1
STATIC_NE_PASS=1
INVENT_PASS=0
BUILD_HOST=NO_NINJA_CL_LINK_OBSERVED
COMPETING_FULL_REBUILD=NOT_STARTED (static audit preferred)
```

Law: `SOURCE_WIRED ≠ RUNTIME_REACHED ≠ PASS`. `NOT_RUN ≠ PASS`. Sealed ledger claims are cited; conflicting receipts are flagged INVESTIGATE — never invented PASS.

---

## 0. Method

| Mode | Action |
|------|--------|
| Static | `F:\rawrxd\CMakeLists.txt`, `F:\rawrxd\src\win32app\*`, ExtHost / AgentSession sources |
| Runtime receipts | Existing CC79 sealed gates + artifact files only |
| Rebuild | **Not performed** (no competing `ninja clean`; host free of ninja/cl but incremental not required for this audit) |

---

## 1) BUILD GRAPH

### Target admission

| Gate | Evidence |
|------|----------|
| Option | `RAWRXD_NATIVE_IDE_EXT` → `RawrXD-Win32IDE-Native-Ext` |
| Sources | `RAWRXD_NATIVE_IDE_EXT_SOURCES = ${RAWRXD_NATIVE_IDE_SOURCES}` + ExtHost TUs |
| CMake | `CMakeLists.txt:3784–3824` (base), `:3986–4118` (Ext) |
| Output | `OUTPUT_NAME RawrXD-Win32IDE-Native-Ext`, never A4F package path (`:3983–3984`) |

### Spot-check: feature → TU → in Ext target?

| Feature | Primary TUs | In `RAWRXD_NATIVE_IDE_SOURCES` / Ext? | Verdict |
|---------|-------------|----------------------------------------|---------|
| Problems UI | `Win32IDE_VSCodeUI.cpp` (ListView 1312), `Win32IDE_lifecycle.cpp`, `Win32IDE_Commands.cpp` (3014 fixture) | YES (`:3784–3824`) | **SOURCE_WIRED** |
| Debug (native) | `Win32IDE_Debugger.cpp`, `Win32NativeDebugBackend.cpp` | YES | **SOURCE_WIRED** |
| Terminal / ConPTY | `Win32TerminalManager.cpp`, `Win32IDE_Commands.cpp` | YES | **SOURCE_WIRED** |
| ExtHost | `js_extension_host.cpp`, `quickjs_*`, `Win32IDE_ExtHostWire.cpp` (`:3989–3995`) | YES (Ext only) | **SOURCE_WIRED** |
| AgentSession | `src/agentic/AgentSession.cpp` via `rawrxd_agentic_backend` (`CMakeLists.txt:5547–5554`) | **NO** — Ext target does **not** `target_link_libraries(... rawrxd_agentic_backend)`; zero `AgentSession` refs under `src/win32app/` | **H01 CONFIRMED** (implemented lib excluded from production Ext IDE) |

### H01 / H02 / H03 flags

| ID | Finding | Proof hook | Class |
|----|---------|------------|-------|
| **H01** | `AgentSession.cpp` compiled into `rawrxd_agentic_backend` only; not linked to `RawrXD-Win32IDE-Native-Ext` | `CMakeLists.txt:4084–4111` link list vs `:5547–5554`; win32app grep = empty | **CONFIRMED** |
| **H01** | PR77 cites `Win32IDE_BuildRunner.cpp`, `problems_aggregator.cpp` — **absent** on F:\ controlling tree | `Test-Path` false this turn; not in Ext sources | **INVESTIGATE** (PR-branch SOURCE_WIRED ≠ F:\ CC79 tree) |
| **H02** | Duplicate debugger control ID namespaces | `Win32IDE.cpp:1435–1453` (`IDC_DEBUGGER_*=1313+`) vs `Win32IDE_Debugger.cpp:21–36` (`IDC_DEBUGGER_*=2100+`); `createDebuggerUI` uses 2100 band | **CONFIRMED** (duplicate ID schema; UI harness looking at 1317/6043 can miss live controls) |
| **H02** | Dual File command ID fallbacks | `Win32IDE_CommandIDs.h:5–9` (`IDM_FILE_NEW=2001…`) vs `Win32IDE_Core.cpp:101–114` (`IDM_FILE_NEW=1001…` ifndef) — Core does not `#include Win32IDE_CommandIDs.h` | **INVESTIGATE** (H13-adjacent) |
| **H03** | View Vulkan / floating-panel stubs | `Win32IDE_Commands.cpp:442–447` `unsupported(...)` | **INVESTIGATE** (explicit unsupported ≠ silent stub for Build/Debug) |

---

## 2) COMMAND GRAPH

Authority header: `Win32IDE_CommandIDs.h`. Router: `Win32IDE::routeCommand` / `handle*Command` in `Win32IDE_Commands.cpp`. Menu build: `Win32IDE.cpp` (~3027+).

| Group | ID | Symbol | Handler | Observable side effect (source) | Flag |
|-------|----|--------|---------|---------------------------------|------|
| File | 2001 | `IDM_FILE_NEW` | `handleFileCommand` → `newFile()` | New buffer / title | OK on Commands path; Core local 1001 = **INVESTIGATE H13** |
| File | 2002 | `IDM_FILE_OPEN` | `openFile()` | Open dialog | same |
| File | 2003 | `IDM_FILE_SAVE` | `saveFile()` | Persist + status bar | same |
| Edit | 2016 | `IDM_EDIT_FIND` | `handleEditCommand` | Find UI | SOURCE_WIRED |
| Edit | 2017 | `IDM_EDIT_REPLACE` | `handleEditCommand` | Replace UI | SOURCE_WIRED |
| View | 2025 / 2034 | `IDM_VIEW_OUTPUT_PANEL` / `IDM_VIEW_PANEL` | `toggleOutputPanel()` | Bottom dock | SOURCE_WIRED (`:448–452`) |
| View | 2029 | `IDM_VIEW_TERMINAL` | create/show terminal panes | HWND show/hide | SOURCE_WIRED |
| View | 2027 | `IDM_VIEW_USE_VULKAN_RENDERER` | `unsupported(...)` | Message only | **H13/H03 INVESTIGATE** (no-op product) |
| Build | **3014** | `IDM_TOOLS_BUILD_PROJECT` | `handleToolsCommand` (`:496+`) | `clearProblems`, terminal pane, optional fixture `cl`, Output feed | SOURCE_WIRED; CC79 Problems still OPEN |
| Debug | **5060** | `IDM_TOOLS_DEBUG_START` | `createLaunchConfiguration` + `startDebugging()` | Native backend launch | SOURCE_WIRED |
| Debug | **10500** | `IDM_DEBUG_START` | `startDebugging()` | Same | SOURCE_WIRED |
| Debug | **6041** | `IDC_DEBUG_START` | `startDebugging()` | Sidebar/toolbar alias | SOURCE_WIRED |
| Debug | 10501 / 6042 / 5061 | STOP aliases | `stopDebugging()` / `detachDebugger` path | `m_nativeDebug->stop` | SOURCE_WIRED |
| Terminal | 3001 | `IDM_TERMINAL_POWERSHELL` | `createTerminalPane` + `startPowerShell` | ConPTY/pipe shell | SOURCE_WIRED |
| Terminal | 3003 | `IDM_TERMINAL_STOP` | `stopTerminal()` | Kill pane process | SOURCE_WIRED |

### H13–H15

| ID | Note | Class |
|----|------|-------|
| **H13** | PR77 tip maps `3014` to GGUF inspector; F:\ CC79 maps `3014` → Build (`CommandIDs.h:51`, menu `Win32IDE.cpp:3093`). Cross-tree harness ID collision. | **CONFIRMED** (documented in `PR77_ACCEPTANCE_001\RECEIPT.md`) |
| **H13** | Core.cpp File IDs 1001 vs menu 2001 | **INVESTIGATE** |
| **H14** | Debug sidebar IDs 6041 routed; harness `DEBUG_VARS_ID6043=0` / `vars1317=-1` on CC79 runlog | **INVESTIGATE** (button may fire; panel content empty) |
| **H15** | Keyboard shortcut matrix vs menu IDs | **UNVERIFIED** (not sampled this audit) |

---

## 3) LIFECYCLE GRAPH

### ConPTY / FORCE_PIPE

| Path | Evidence | Class |
|------|----------|-------|
| Interactive prefer ConPTY | `Win32TerminalManager::startCommandLine` `:91–96` → `CreatePseudoConsole` `:99–132` | SOURCE_WIRED |
| Fixture FORCE_PIPE | Env `RAWRXD_TERMINAL_FORCE_PIPE=1` → skip ConPTY, `bounded_ms=120000`, `startPipe` (`:79–88`) | SOURCE_WIRED |
| Build sets FORCE_PIPE | `Win32IDE_Commands.cpp:591–596` around fixture `cl` | SOURCE_WIRED |
| **H27 VS_UNICODE_OUTPUT** | Scrub in cmdline `set VS_UNICODE_OUTPUT=` (`Commands.cpp:567–575`); isolated proof `COMPILER_ROOT_CAUSE_001.txt` | **CONFIRMED historical** |

Absorb:

```
COMPILER_ROOT_CAUSE_001 = CONFIRMED
ROOT = cl stalls under redirected pipes when VS_UNICODE_OUTPUT inherited
PRODUCT_FIX_SOURCE = Commands.cpp + TerminalManager.cpp (+ IDE feed patches)
IDE_FEED_ON_REBUILT_EXE = NOT_VERIFIED (candidate rebuild pending; tip_003 not controlling)
```

### WaitForDebugEvent thread ownership

| Fact | Evidence |
|------|----------|
| Event thread owns `CreateProcess(DEBUG_*)` | `Win32NativeDebugBackend.cpp:105–107`, `:693–711` |
| Loop | `WaitForDebugEvent(&ev, 200)` `:729` |
| UI marshal | `kRawrxdNativeDebugState` (`Win32IDE.h:54–55`); Core comments `:1571` |
| Stop | `stop(bool terminate)` → `TerminateProcess` + `m_stopRequested` (`:133+`) |

### ExtHost shutdown

| Stage | Symbol / path |
|-------|----------------|
| CLI wire | `RawrXD_ExtHost_HandleCmdLine` `Win32IDE_ExtHostWire.cpp:146–249` |
| Deactivate/unload on `--ext-quit` | `:238–243` `deactivateExtension` + `unloadExtension` |
| Quit | `PostQuitMessage(0)` `:248` |
| JS shutdown message | `js_extension_host.cpp` Shutdown type |
| Sealed smoke | `logs\ext_smoke_run_20261109-051316.txt` RECEIPT_A all OK; file `ext_runtime_receipt.txt` currently overwritten by malformed B | **INVESTIGATE** receipt durability |

Reload/crash recovery beyond smoke `RELOAD_OK=1` on happy path: **UNVERIFIED** (PR79 theme).

### AgentSession cancel

| Fact | Evidence | Class |
|------|----------|-------|
| Source exists | `src/agentic/AgentSession.cpp` / `.h` | SOURCE exists |
| Linked into Ext IDE | No | **H01 CONFIRMED** |
| Cancel API in AgentSession.cpp | Grep cancel/KillSession = none | **INVESTIGATE** (PR78 cancel/recovery NOT_RUN) |
| Adjacent cancel | Chat/agentic loop: `IDM_AGENT_STOP` / `IDM_AGENTIC_LOOP_CANCEL` in Commands router — not AgentSession ledger | SOURCE_WIRED alternate path only |

### HWND stale / H16–H18, H27–H30

| ID | Finding | Class |
|----|---------|-------|
| **H16** | Problems/terminal feed patches claim HWND-null-safe path in source notes (`COMPILER_ROOT_CAUSE_001` PRODUCT_FIX); CC79 image pre-dates full IDE remeasure | **INVESTIGATE** |
| **H17** | Native debug posts to UI thread (designed); terminal callbacks → Problems insert via PostMessage noted in TerminalManager comments | SOURCE intent OK; E2E OPEN |
| **H18** | Cancelled generation posts after stop (chat path has generation fences in `Win32IDE.cpp`); ExtHost post-quit messages | **INVESTIGATE** |
| **H27** | VS_UNICODE_OUTPUT | **CONFIRMED** |
| **H28** | Historical PeekNamedPipe/`m_running` drain gap; source now blocking ReadFile to EOF (`TerminalManager` drain) | CONFIRMED historical; product EXE remeasure **NOT_VERIFIED** |
| **H29/H30** | Timeout: `TerminateProcess(m_hProcess)` only (`:459–462`); job-object / descendant kill not evidenced | **INVESTIGATE** |

---

## 4) FAILURE GRAPH

### Build fixture (3014 + RAWRXD_PROBLEMS_FIXTURE)

| Disposition | Source path | Receipt |
|-------------|-------------|---------|
| Request | `COMPILER_CAPTURE_RECEIPT.txt` write at launch (`Commands.cpp:577–588`) | Path exists; content depends on last run |
| Timeout (120s FORCE_PIPE) | `monitorProcessThread` WAIT_TIMEOUT → TerminateProcess → `disposition=timeout` (`TerminalManager.cpp:455–503`) | Appends `PROCESS_EXIT` / `BUILD_RESULT=` |
| Success/failure | Same receipt + stdout bytes | |
| Cancel (user Kill Terminal) | `IDM_TERMINAL_STOP` → `stop()` | No dedicated BUILD_CANCEL receipt schema found → **MISSING** formal cancel receipt |
| CC79 Problems outcome | items=0 | `MASTER_STATUS_CC79.md`, `PROBLEMS_PANEL_GATE.md` → OPEN / NOT_PASS |

### Debug stop

| Path | Receipt |
|------|---------|
| Headless `debug_backend_verify` | `artifacts\debug_backend_verify_CC79_receipt.txt` — BACKEND_HEADLESS=PASS, EXIT_PROCESS observed |
| IDE UI Stop (10501/6042/5061) | CC79 runlog posts STOP=True but `SESSION_REAL_VIA_IDE_UI=0`, vars empty — **no IDE stop receipt with SESSION_REAL** → **MISSING** |
| Backend `stop(true)` | Source only; joins event thread | |

### ExtHost failure

| Path | Receipt |
|------|---------|
| Malformed isolate | Smoke B FAULT_ISOLATED=1 | Sealed in runlog |
| Live `ext_runtime_receipt.txt` | Currently malformed-B residue | **INVESTIGATE** (non-durable single path) |

---

## 5) ACCEPTANCE GRAPH (CC79)

SHA: `CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4`

### Sealed PASS gates (ledger → receipt)

| Gate | Ledger | Receipt / proof path | Notes |
|------|--------|----------------------|-------|
| EXTENSIONHOST | `MASTER_STATUS_CC79.md` PASS; `EXTENSIONHOST_GATE.md` | **Authoritative runlog** `logs\ext_smoke_run_20261109-051316.txt` (RECEIPT_A); alias claim `FULL_FEATURE_ONESHOT_001\artifacts\ext_runtime_receipt.txt` **clobbered** by smoke B | PASS on runlog evidence; file path fragile → INVESTIGATE durability |
| CHAT_AIM 7/7 | MASTER + `NATIVE_EDITOR_CHAT_GATE.md` | `artifacts\CHAT_CTRL_ENTER_RECEIPT.txt` (TIP_SHA256=CC79…) + `chat_ctrl_enter_run_20261109-051150.txt` | Sealed PASS |
| TERMINAL | MASTER + `TERMINAL_GATE.md` | `artifacts\term_smoke_receipt_CC79.txt` (CONPTY, OUT_LEN=390) | Sealed PASS (smoke scope; full interactive matrix NOT_RUN) |
| OUTPUT_GUI | MASTER + `OUTPUT_PANEL_GATE.md` PASS | Gate cites `artifacts\CC79_FOUR_PANEL_DEBUG_UI_RECEIPT.txt`; **that file now holds tip_003 SHA `9BEBB003…` FAIL** | **INVESTIGATE** — use timed runlog `cc79_four_panel_debug_ui_run_20261109-053132.txt` (visEdit=430) as CC79-era measure; do not treat current receipt filename as CC79 seal |
| DEBUG_HEADLESS | MASTER | `artifacts\debug_backend_verify_CC79_receipt.txt` BACKEND_HEADLESS=PASS SESSION_REAL=1 | Sealed PASS (headless only) |

### Open / FAIL gates

| Gate | Status | Proof |
|------|--------|-------|
| PROBLEMS_UI | **OPEN** / NOT_PASS | MASTER; `PROBLEMS_PANEL_GATE.md` items=0; runlog id1312=0 |
| IDE_DEBUG_UI / DEBUG_CONSOLE UI | **OPEN/FAIL** | `DEBUG_CONSOLE_GATE.md` IDE_DEBUG_UI=FAIL; four-panel receipt DEBUG hooks empty |
| FOUR_PANEL | **OPEN** / FAIL_CLOSED_GAPS | `FOLLOWUP_CC79_FOUR_PANEL.md`; `four_panel_hwnd_probe_CC79.txt`; conjunction Output∧Problems∧Terminal∧Debug UI not closed |
| PRODUCT_PASS / CERTIFIED / PROMOTE | **0** | All governing docs |

Static ≠ PASS. Tip_003/004 must not replace CC79.

---

## 6) PR theme reconcile (local evidence only)

| PR | Theme | On CC79 / F:\ tree | Verdict |
|----|-------|--------------------|---------|
| **#77** | ConPTY / Problems / Output / four-panel | ConPTY **RUNTIME_REACHED** on CC79 term-smoke PASS; Output GUI **RUNTIME_REACHED** (CC79-era runlog) with receipt-path drift; Problems **SOURCE_WIRED**, RUNTIME items=0; four-panel **NOT closed**; PR branch BuildRunner/aggregator **absent** on F:\ | SOURCE_WIRED partial; RUNTIME partial; `MERGE_AUTHORIZED=0` (`PR_INTEGRATION_TRACK_001`) |
| **#78** | AgentSession ownership | Source in `rawrxd_agentic_backend`; **not** in Ext IDE link; cancel E2E **NOT_RUN** | SOURCE exists ≠ E2E; ownership **UNVERIFIED** in product EXE |
| **#79** | ExtHost | CC79 EXT smoke PASS (load/activate/cmd/deactivate/reload happy + malformed isolate); worker crash recovery / KillHost product path **UNVERIFIED** | EXT PASS **scope-limited**; reload/crash recovery **UNVERIFIED** |
| **#75** | Native linker 16 tests | Inventory: committed, **not executed** | **UNVERIFIED** |
| **#76** | Deep2 consolidation | Held / CONFLICTING | **TIP_CLIMB=HOLD** note only; no promote |

---

## 7) Counts + top 10 risks

```
CONFIRMED=8
INVESTIGATE=14
UNVERIFIED=5
SEALED_PASS_GATES_CITED=5
OPEN_FAIL_GATES=3
PROMOTE=0
```

### Top 10 evidence-backed risks

1. **H01 AgentSession excluded from Ext IDE** — lib exists; product EXE does not link it (`CMakeLists` Ext link list vs `rawrxd_agentic_backend`).
2. **Problems feed still OPEN on CC79** — HWND 1312 present, items=0; VS_UNICODE_OUTPUT root cause CONFIRMED but IDE candidate rebuild / IDE_FEED not re-sealed on CC79.
3. **H02 debugger IDC split (1313+ vs 2100+)** — harness looking at 1317/6043 reports empty while `createDebuggerUI` uses 2100 band.
4. **FOUR_PANEL + IDE_DEBUG_UI not closed** — headless debug PASS ≠ IDE UI SESSION_REAL.
5. **OUTPUT_GUI receipt filename clobbered by tip_003** — ledger PASS must not silently inherit from overwritten `CC79_FOUR_PANEL_DEBUG_UI_RECEIPT.txt`.
6. **H27/H28/H29 timeout/env lifecycle** — FORCE_PIPE+scrub SOURCE_WIRED; descendant process kill and post-rebuild IDE feed **NOT_VERIFIED**.
7. **H13 command-ID skew** — Core File 1001 vs menu 2001; PR77 vs F:\ meaning of 3014.
8. **ExtHost receipt non-durable** — single `ext_runtime_receipt.txt` overwritten by malformed probe after PASS_A.
9. **PR77 source themes missing on F:\** — BuildRunner / problems_aggregator files absent → cannot claim PR77 SOURCE_WIRED on controlling tree.
10. **PR75 16 native-linker tests UNVERIFIED; PR76 Deep2 HOLD** — do not fold into CC79 product PASS.

---

## 8. Non-claims

```
STATIC_AUDIT ≠ PASS
TIP_003_004 ≠ CONTROLLING
A4F ≠ MUTATED
PR77_78_79_MERGE ≠ AUTHORIZED
CROSS_SHA_INHERIT = 0
f49b636b_BUILD_HOST_RECLAIM = NOT_OBSERVED_AS_NINJA (no competing rebuild started)
```

## Audit path

`F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\FIVE_LAYER_SOURCE_AUDIT_001.md`
