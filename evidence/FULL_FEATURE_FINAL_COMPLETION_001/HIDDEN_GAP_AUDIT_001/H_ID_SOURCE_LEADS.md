# H_ID_SOURCE_LEADS — promising H-IDs → concrete code locations

```
ASOF_UTC=2026-11-09T12:30:00Z
PROMOTE=0
CERTIFIED=0
CONTROLLING_TIP=CC79
SOURCE=STATIC_RE + sealed local receipts
CONFIRMED_ONLY_WITH_RECEIPT=1
```

Companion: `SOURCE_GRAPH_AUDIT_NOTES.md`.

---

## H01–H12 — Build / source admission

| ID | Gap (register) | Concrete lead | Path:line / symbol |
|----|----------------|---------------|--------------------|
| H01 | Source excluded from production target | `AgentSession.cpp` compiled into `rawrxd_agentic_backend` only; **not** linked by `RawrXD-Win32IDE-Native-Ext` | `F:\rawrxd\CMakeLists.txt:5547–5554` (lib); Ext link block `:4084–4111` (no agentic_backend) |
| H01 | Ext TU completeness skip | Missing listed source → Ext target SKIPPED | `CMakeLists.txt:3997–4002`, `:4120` |
| H02 | Duplicate implementations | Ext uses `js_extension_host.cpp`; headless/production siblings not in Ext SOURCES | `CMakeLists.txt:3989` vs `src/core/js_extension_host_headless_impl.cpp`, `js_extension_host_production.cpp` |
| H02 | Agent dual surface | `Win32IDE_AgentCommands.cpp` / AgenticBridge in Native sources vs `AgentSession` library | `CMakeLists.txt:3799–3804` vs `:5554` |
| H03 | Stub shadows production | Unknown-module require stub; QuickJS type-stub comments | `src/core/js_extension_host.cpp:72`, `:2477–2478` |
| H03 | Disabled test path | `if(FALSE) test_terminal` | `CMakeLists.txt:4129–4138` |
| H04 | Feature flag off in release | `RAWRXD_NATIVE_IDE_EXT` default OFF | `CMakeLists.txt:329` |
| H04 | Stub define forced off for Ext | `RAWR_QUICKJS_STUB=0` when Ext builds | `CMakeLists.txt:4077–4078` |
| H05 | Missing deps / clean checkout | Ext requires QuickJS dir (`quickjs_ng` or `quickjs`) | `CMakeLists.txt:4005–4011` |
| H08 | Inherited env affecting tools | Build fixture scrubs `VS_UNICODE_OUTPUT` / `VC_CLEAR` | `Win32IDE_Commands.cpp:567–573` |
| H09 | Optional unresolved paths | ggml / Deep2 / security / hardening optional `if(TARGET)` | `CMakeLists.txt:4095–4111` |
| H10 | Branch-incompatible IDs | F:\ `3014=Build`; G:\ `3014=GGUF Inspector` | F: `Win32IDE_CommandIDs.h:51`; G: `Win32IDE.cpp:735` + `Win32IDE_Commands.cpp:1209` |
| H11 | Generated header dependency | Ext depends on `rawrxd_chat_route_menu` generated header | `CMakeLists.txt:4049–4050`, `:4094` |
| H12 | Reproducible SHA | Candidate SHA sealed in disposition receipts (not re-hashed here) | `INTEG004_ACCEPTANCE_DISPOSITION.md` / EXT receipt |

---

## H13–H18 — Command / HWND / thread

| ID | Gap | Concrete lead | Path:line / symbol |
|----|-----|---------------|--------------------|
| H13 | Wrong/missing handlers | Build menu → `handleToolsCommand` / `IDM_TOOLS_BUILD_PROJECT` | `Win32IDE.cpp:3093`; `Win32IDE_Commands.cpp:207–209`, `:496` |
| H13 | Dual build namespaces | `IDM_TOOLS_BUILD_PROJECT 3014` **and** `IDM_BUILD_COMPILE 5001`… | `Win32IDE_CommandIDs.h:51`, `:71–75` |
| H13 | Cross-tree 3014 collision | G:\ GGUF vs F:\ Build (see H10) | PR77 receipt `evidence\PR77_ACCEPTANCE_001\RECEIPT.md:55–59` |
| H14 | Toolbar no-op | (not exhaustively mapped this pass) | Sample via same `WM_COMMAND` router in `Win32IDE_Commands.cpp` |
| H15 | Keyboard bypass / wrong ID | G:\ accel maps Ctrl+F12 → **3014** (`IDM_EDITOR_GOTO_IMPLEMENTATION`); F:\ lacks Accelerators TU | `G:\~dev\rawrxd\src\win32app\Win32IDE_Accelerators.cpp:49`, `:140` |
| H16 | Stale HWND after destroy | Terminal callbacks nulled before pane destroy | `Win32IDE_Core.cpp:5085–5113` |
| H17 | Worker touches UI | Terminal path posts `kRawrxdTerminalUiUpdate` (WM_APP+110) | `Win32IDE.cpp:3437–3444`; `Win32IDE.h:248`; drain `Win32TerminalManager.cpp:429–430` |
| H18 | Posted msg after cancel | UI marshal + quit-before-loop ordering | lifecycle `:429–464`; `ExtHostWire.cpp:248` + `main_win32.cpp:190–208` |

---

## H27–H30 — Compiler / pipe (historical scrub)

| ID | Gap | Concrete lead | Path:line / symbol |
|----|-----|---------------|--------------------|
| H27 | Bad inherited env | `set VS_UNICODE_OUTPUT=` in fixture cmdline; receipt `SCRUB=VS_UNICODE_OUTPUT` | `Win32IDE_Commands.cpp:567–585` |
| H27 | **CONFIRMED historical** | CC79 empty Problems; integ_004 PASS after scrub | `PROBLEMS_PANEL_GATE.md`; `LINEAGE_RECONCILE_EA5D_CC79_INTEG004.md:22`; `INTEG004_ACCEPTANCE_DISPOSITION.md` |
| H28 | Pipe backpressure / drop | Drain via blocking `ReadFile` to EOF (comment: do not gate on `m_running`) | `Win32TerminalManager.cpp:416–431` |
| H28 | FORCE_PIPE transport | `RAWRXD_TERMINAL_FORCE_PIPE=1` around `startCommandLine` | `Win32IDE_Commands.cpp:590–595` |
| H29 | Child survives cancel | `pane->manager->stop()` before relaunch; descendant tree kill **UNVERIFIED** | `Win32IDE_Commands.cpp:589` |
| H30 | Timeout parent≠descendants | Harness `WaitForExit(20000)` then force-kill **host** only | `ext_smoke_oneshot.ps1:46–48` |

---

## H43–H52 — ExtensionHost / quit / cleanup

| ID | Gap | Concrete lead | Path:line / symbol |
|----|-----|---------------|--------------------|
| H43 | Activate never runs | Wire: `activateExtension` after `loadPath` | `Win32IDE_ExtHostWire.cpp:200–209`, `:193–198` |
| H44 | Worker IPC handshake | In-proc QuickJS host (`JSExtensionHost::instance`) — not separate IPC worker in this wire | `ExtHostWire.cpp:55–66`; `include\quickjs_extension_host.h` |
| H46 | Wrong-thread commands | Comment: JS executeCommand can hang; uses `invokeRegisteredCommand` | `ExtHostWire.cpp:216–221` |
| H48 | Crash kills IDE | Malformed path sets `faultIsolated` if load fails & process alive | `ExtHostWire.cpp:178–183`; smoke B receipt FAULT_ISOLATED=1 |
| H49 | Unload leaves callbacks | `deactivateExtension` + `unloadExtension` on `--ext-quit` | `ExtHostWire.cpp:238–244` |
| H50 | Reload duplicates | `--ext-reload` deactivate→activate | `ExtHostWire.cpp:230–237` |
| H51 | Process survives shutdown | **CONFIRMED** integ_004: `FORCE_KILL=1`, `EXT_CLEANUP=FAIL` | `INTEG004_EXT_REVERIFY_RECEIPT.md:33–43`; runlog `:9` |
| H51 | Static quit path | `PostQuitMessage(0)` then `runMessageLoop` drain | `ExtHostWire.cpp:248`; `main_win32.cpp:190–208`; `Win32IDE_lifecycle.cpp:889–933` |
| H51 | Possible keep-alive | Per-ext `eventLoopThread` | `quickjs_extension_host.h:159–160` |
| H52 | Crash restart | `handleExtensionCrash` API present | `quickjs_extension_host.h:350`; impl in `quickjs_extension_host.cpp` |

Runtime type name: **`QuickJSExtensionRuntime`** (no `ProductExtensionRuntime` symbol).

---

## Acceptance anchors (not H-IDs, but controlling)

| Fact | Receipt | Status |
|------|---------|--------|
| Problems PASS on integ_004 | `INTEG004_ACCEPTANCE_DISPOSITION.md` | CONFIRMED candidate-only |
| Problems FAIL on CC79 | same + lineage | CONFIRMED controlling |
| EXT_CLEANUP FAIL | `INTEG004_EXT_REVERIFY_RECEIPT.md` | CONFIRMED on `47451F24…` |
| PROMOTE / tip move | AUDIT_LAW / disposition | `PROMOTE=0`, `TIP_MOVE_AUTHORIZED=0` |

---

## Priority follow-ups (static → next executable gate)

1. **H51 / EXT_CLEANUP** — prove why `PostQuitMessage` does not yield harness `ExitCode=0` within 20s on tip_ext (nested pump vs non-joined QuickJS thread). Existing FAIL receipt; fix lane separate.
2. **H10/H13/H15** — freeze one command-ID SSOT before four-panel harness binds `3014`.
3. **H01** — decide whether `AgentSession` must link into Native-Ext or remain library-only (PR #78 surface).
4. **H27** — keep as historical; do not re-open as new HIDDEN_GAP CONFIRMED.
