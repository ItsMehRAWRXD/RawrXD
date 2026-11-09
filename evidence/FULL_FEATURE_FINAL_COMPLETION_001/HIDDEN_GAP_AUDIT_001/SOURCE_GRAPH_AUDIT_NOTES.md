# SOURCE_GRAPH_AUDIT_NOTES — five-layer static RE

```
ASOF_UTC=2026-11-09T12:30:00Z
MOTD_ACK=1
MODE=STATIC_ONLY
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
CONTROLLING_TIP=CC79
CANDIDATE=INTEG_004
CANDIDATE_SHA=47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F
INVENT_CONFIRMED_DEFECT=0
CROSS_SHA_PASS_INHERITANCE=0
RUNTIME_EXECUTION=NOT_RUN_THIS_WORKER
```

Status vocabulary: **INVESTIGATE** = static lead with file:line; **CONFIRMED** = only when tied to an existing sealed receipt; **UNVERIFIED** = required behavior not demonstrated on the cited SHA.

Authority trees: `F:\rawrxd` (primary tip_ext / oneshot); `G:\~dev\rawrxd` (compare-only for ID collisions).

---

## 1. Build graph (H01–H12)

### Target admission — `RawrXD-Win32IDE-Native-Ext`

| Gate | Citation | Finding |
|------|----------|---------|
| Option default OFF | `F:\rawrxd\CMakeLists.txt:329` | `RAWRXD_NATIVE_IDE_EXT` defaults OFF — tip_ext is optional; slim Native remains A4F lineage. **INVESTIGATE H04**. |
| Base TU list | `CMakeLists.txt:3784–3824` (`RAWRXD_NATIVE_IDE_SOURCES`) | Includes `main_win32.cpp`, `Win32IDE_Commands.cpp`, `Win32TerminalManager.cpp`, Agent* bridges (`Win32IDE_AgenticBridge.cpp`, `Win32IDE_AgentCommands.cpp`, `Win32IDE_AgenticLoopBridge.cpp`), lifecycle, GGUF loaders. |
| Ext delta | `CMakeLists.txt:3986–3996` | Appends `js_extension_host.cpp`, `extension_polyfill_engine.cpp`, `plugin_signature.cpp`, `vscode_extension_api.cpp`, `quickjs_extension_host.cpp`, `quickjs_vscode_bindings.cpp`, **`Win32IDE_ExtHostWire.cpp`**. |
| Completeness gate | `CMakeLists.txt:3997–4002`, `4013`, `4120` | Missing any listed source OR QuickJS dir → target **SKIPPED** (WARNING). **INVESTIGATE H01/H05/H09**. |
| QuickJS provider | `CMakeLists.txt:4005–4011` | Prefer `3rdparty/quickjs_ng`, else `3rdparty/quickjs`. |
| Compile defs | `CMakeLists.txt:4071–4079` | `RAWR_HAS_QUICKJS=1`, `RAWR_QUICKJS_STUB=0`, `RAWRXD_NATIVE_IDE_EXT=1`. Stub compile path intentionally disabled for Ext. |
| Optional link | `CMakeLists.txt:4095–4111` | `rawrxd_production_hardening`, `rawrxd_security`, `ggml`, `rawrxd_agent_esp`, `deep2_engine_lib` — each gated `if(TARGET …)`. **INVESTIGATE H09** (unresolved/optional). |
| Output isolation | `CMakeLists.txt:4113–4116` + comment `:3982–3984` | `OUTPUT_NAME RawrXD-Win32IDE-Native-Ext`; must not overwrite `package\RawrXD-Win32IDE-Native.exe` (A4F immutable). |

### Symbol / feature admission (requested names)

| Requested | Static disposition | Citation |
|-----------|--------------------|----------|
| `Win32IDE_Commands.cpp` | **ADMITTED** into Native + Native-Ext via `RAWRXD_NATIVE_IDE_SOURCES` | `CMakeLists.txt:3796`, `3988` |
| `ExtHostWire` (`Win32IDE_ExtHostWire.cpp`) | **ADMITTED** only into Native-Ext | `CMakeLists.txt:3995`; wired from `main_win32.cpp:184–193` under `#if RAWRXD_NATIVE_IDE_EXT` |
| `TerminalManager` | Product name is **`Win32TerminalManager`** (not Qt `TerminalManager`) | `CMakeLists.txt:3794`; impl `src/win32app/Win32TerminalManager.cpp` |
| `AgentSession*` | Source exists `src/agentic/AgentSession.{h,cpp}` but lives in **`rawrxd_agentic_backend`** (`CMakeLists.txt:5547–5554`). Native-Ext **does not** `target_link_libraries(… rawrxd_agentic_backend)`. IDE agent path uses `Win32IDE_Agent*` TUs instead. **INVESTIGATE H01/H02** (duplicate agent surfaces; `AgentSession` not in tip_ext link set). |
| `ProductExtensionRuntime*` | **No symbol** `ProductExtensionRuntime` in `F:\rawrxd`. Closest product type: **`QuickJSExtensionRuntime`** | `F:\rawrxd\include\quickjs_extension_host.h:141–185`; created in `src/modules/quickjs_extension_host.cpp` (`createRuntime`) |

### Obvious stubs / optional / disabled paths

| Lead | Citation | Status |
|------|----------|--------|
| `if(FALSE)` `test_terminal` | `CMakeLists.txt:4129–4138` | Disabled harness; not release. **INVESTIGATE H03** (orphan test path). |
| JS require fallback stub string | `src/core/js_extension_host.cpp:2477–2478` | Emits stub module for unknown `require()` — polyfill fallback, not host disable. **INVESTIGATE H03**. |
| Minimal QuickJS type stubs comment | `js_extension_host.cpp:72` | Compile-without-engine comments; Ext target forces `RAWR_QUICKJS_STUB=0`. **INVESTIGATE H03/H04**. |
| Headless/production alternate TUs | `src/core/js_extension_host_headless_impl.cpp`, `js_extension_host_production.cpp` | **Not** in `RAWRXD_NATIVE_IDE_EXT_SOURCES` (only `js_extension_host.cpp`). **INVESTIGATE H02**. |
| Branch ID namespace divergence | `G:\~dev\rawrxd` vs `F:\rawrxd` (see §2) | **INVESTIGATE H10**. |

No build-graph item above is marked **CONFIRMED** defect — static leads only.

---

## 2. Command graph (H13–H15, H43–H52)

### F:\rawrxd — Build = 3014

| Item | Citation |
|------|----------|
| Menu ID | `Win32IDE_CommandIDs.h:51` — `#define IDM_TOOLS_BUILD_PROJECT 3014` |
| Menu bind | `Win32IDE.cpp:3093` — `AppendMenuA(…, IDM_TOOLS_BUILD_PROJECT, "&Build Project")` |
| Router | `Win32IDE_Commands.cpp:207–209` → `handleToolsCommand` |
| Handler | `Win32IDE_Commands.cpp:496+` — `case IDM_TOOLS_BUILD_PROJECT` / `buildTrace("BUILD_COMMAND_ENTRY id=3014")` |

Also present: alternate build IDs `IDM_BUILD_COMPILE 5001` etc. (`Win32IDE_CommandIDs.h:71–75`) — second build namespace. **INVESTIGATE H13**.

### G:\~dev\rawrxd — GGUF Inspector = 3014 (cross-tree collision)

| Item | Citation |
|------|----------|
| Define | `G:\~dev\rawrxd\src\win32app\Win32IDE.cpp:735` — `#define IDM_TOOLS_GGUF_INSPECTOR 3014` |
| Menu | same file `:1025` — `"GGUF Model &Inspector"` |
| Handler | `G:\~dev\rawrxd\src\win32app\Win32IDE_Commands.cpp:1209–1212` — `case 3014: ShowGGUFInspectorPanel()` |
| Build on G: tree | `Win32IDE_Core.cpp:97–98` — `IDM_BUILD_PROJECT 2801` (different ID) |

**INVESTIGATE H13/H10:** same numeric `3014` means Build on F:\ oneshot tip vs GGUF Inspector on G:\ PR tip. Prior receipt already warns: `evidence\PR77_ACCEPTANCE_001\RECEIPT.md:55–59` — do not map F:\ Build crash onto PR77 without rebinding. **Not a new CONFIRMED defect** — cross-tree namespace hazard.

### Keyboard / accel (H15)

| Tree | Finding |
|------|---------|
| F:\rawrxd | **No** `Win32IDE_Accelerators.cpp` under `src/win32app`. |
| G:\~dev\rawrxd | `Win32IDE_Accelerators.cpp:49` `#define IDM_EDITOR_GOTO_IMPLEMENTATION 3014`; `:140` Ctrl+F12 → 3014. |

**INVESTIGATE H15:** on G:\ tree, accel 3014 collides with GGUF inspector ID; F:\ Build 3014 has no matching accel TU in-tree.

### `--ext-quit` path (H43–H52 lifecycle commands)

| Step | Citation |
|------|----------|
| CLI parse `--ext-quit` | `Win32IDE_ExtHostWire.cpp:170–173` sets `doQuit=true` |
| Load/activate/cmd | `:178–228` (`loadPath`, `activateExtension`, `invokeRegisteredCommand`) |
| Quit unload branch | `:238–244` — if `doQuit && extensionId && activateOk` → `deactivateExtension` + `unloadExtension` |
| Quit signal | `:248` — `if (doQuit) PostQuitMessage(0);` |
| WinMain wire | `main_win32.cpp:184–193` — calls `RawrXD_ExtHost_HandleCmdLine` then still enters `runMessageLoop()` (`:208`) to drain |
| Message loop | `Win32IDE_lifecycle.cpp:889–933` — `GetMessageA` until quit |

ExtHostWire comment `:216–217` notes JS `executeCommand` can hang without a pump; product path uses C++ `invokeRegisteredCommand` trampoline.

**INVESTIGATE H43/H49/H51:** receipt fields can show INIT/LOAD/ACTIVATE/CMD/DEACTIVATE/RELOAD=1 while process still fails clean exit (see §3 / §5).

---

## 3. Lifecycle graph (H16–H18, H27–H30, H51)

### Terminal onOutput → WM_APP UI marshal

```
Win32TerminalManager::readOutputThread
  → onOutput(chunk)                          Win32TerminalManager.cpp:416–431
  → PostMessageA(kRawrxdTerminalUiUpdate)    Win32IDE.cpp:3437–3444
  → WindowProc case kRawrxdTerminalUiUpdate  Win32IDE_lifecycle.cpp:429–464
  → onTerminalOutput / ingest diagnostics    Win32IDE.cpp:4148–4161
```

| Detail | Citation |
|--------|----------|
| Message ID | `Win32IDE.h:248` — `kRawrxdTerminalUiUpdate = WM_APP + 110` |
| Callback clear before destroy | `Win32IDE_Core.cpp:5085–5113` — null `onOutput/onError/onFinished` then `stop()` (UAF / stale HWND mitigation). **INVESTIGATE H16/H18** (pattern present; runtime soak UNVERIFIED). |
| Worker→UI | Output posted via `PostMessageA` (not direct control touch). **H17** lead mitigated in this path; other panels may differ. |

### FORCE_KILL / ext-quit cleanup failure context

| Evidence | Citation | Status |
|----------|----------|--------|
| Harness wait 20s then `Stop-Process -Force` | `evidence\FULL_FEATURE_ONESHOT_001\harness\ext_smoke_oneshot.ps1:46–50` | Mechanism |
| integ_004 runlog | `…\logs\ext_smoke_tip_final_integ_004.txt:9` — `SMOKE_A_EXIT=-1 FORCE_KILL=1 HWND=0x59248136` | **CONFIRMED** measured (receipt) |
| Disposition | `INTEG004_EXT_REVERIFY_RECEIPT.md:33–43` — `FORCE_KILL=1`, `EXT_CLEANUP=FAIL`, `EXTENSIONS=FAIL` | **CONFIRMED** |
| Static hypothesis | `PostQuitMessage(0)` at ExtHostWire `:248` **before** `runMessageLoop`; nested pumps during activate/cmd may consume `WM_QUIT`, or extension `eventLoopThread` (`quickjs_extension_host.h:159`) may keep process/HWND alive | **INVESTIGATE H18/H51** — not proven by this static worker |

Receipt also shows `PROCESS_ALIVE=1` written **before** quit drain completes (`ExtHostWire.cpp:246` then `:248`) — expected for receipt timing; not alone proof of hang.

### Compiler child / pipe lifecycle (H27–H30) — overlaps failure graph

Fixture path uses `RAWRXD_TERMINAL_FORCE_PIPE`, `closeInput()`, scrub env — see §4. Child-survivor / timeout descendant kill: **UNVERIFIED** in this static pass.

---

## 4. Failure graph — `VS_UNICODE_OUTPUT` / pipe scrub

**Do not invent as new defect.** Owner register + local receipts treat this as historical on CC79 / fixed on integ_004 candidate.

| Layer | Citation | Disposition |
|-------|----------|-------------|
| Product scrub in Build handler | `Win32IDE_Commands.cpp:567–573`, `:585` (`SCRUB=VS_UNICODE_OUTPUT`), `:590–598` (`FORCE_PIPE` + `closeInput`) | Source-wired on F:\ tip track |
| Drain-to-EOF (not `m_running` gate) | `Win32TerminalManager.cpp:416–419` comment + `:424–431` | Source-wired |
| Diagnostic ingest | `Win32IDE.cpp:4148–4161` → `ingestTerminalDiagnostics` / `DIAGNOSTIC_PARSED` / `PROBLEM_ADDED` (`:176–184`) | Source-wired |
| Historical root cause | `PROBLEMS_PANEL_GATE.md:24–40`; `LINEAGE_RECONCILE_EA5D_CC79_INTEG004.md:22` | Documented |
| CC79 Problems | `INTEG004_ACCEPTANCE_DISPOSITION.md:11` — `CC79_PROBLEMS_UI=FAIL` | **CONFIRMED** historical |
| integ_004 Problems | same `:10` — `CANDIDATE_PROBLEMS_UI=PASS`; lineage `:17–18` items=3, click | **CONFIRMED** on candidate SHA only |

```
CONFIRMED_HISTORICAL_CC79 = VS_UNICODE_OUTPUT hang (empty Problems)
CONFIRMED_FIXED_ON_INTEG_004_CANDIDATE = Problems UI PASS (SHA 47451F24…)
NOT_NEW_DEFECT_FOR_THIS_AUDIT = 1
NO_CROSS_SHA_PASS_INHERITANCE = 1
```

---

## 5. Acceptance graph

| Receipt | Path | What it proves | What it does **not** prove |
|---------|------|----------------|----------------------------|
| Problems PASS (candidate) | `INTEG004_ACCEPTANCE_DISPOSITION.md` | integ_004 Problems UI PASS; eligible for further reverify | Controlling tip move; product PASS |
| Lineage board | `LINEAGE_RECONCILE_EA5D_CC79_INTEG004.md` | CC79 controlling; integ_004 Problems-only candidate; EXT/CHAT/TERM/OUTPUT/DEBUG on 47451F24 = NEEDS_REVERIFY | Integrated acceptance |
| EXT cleanup FAIL | `INTEG004_EXT_REVERIFY_RECEIPT.md` + `logs\ext_smoke_tip_final_integ_004.txt` | On 47451F24: receipt lifecycle bits=1 but `FORCE_KILL=1` → `EXT_CLEANUP=FAIL` / `EXTENSIONS=FAIL` | CC79 EXT re-PASS inheritance |
| CC79 controlling | `AUDIT_LAW.md`; `INTERIM_LOCAL_FINDINGS.md` | Tip authority unchanged | Maturity bump |

```
INTEG_004_PROBLEMS_PASS ≠ CONTROLLING_TIP ≠ PRODUCT_PASS ≠ CERTIFIED ≠ PROMOTE
EXT_CLEANUP_FAIL (47451F24) = CONFIRMED via INTEG004_EXT_REVERIFY_RECEIPT
CC79 remains CONTROLLING_TIP
MAJOR_INTEGRATED_ACCEPTANCE = NOT_DEMONSTRATED
```

Note: harness runlog disposition line may print `EXT_LOAD=FAIL` when `ExitCode != 0` (`ext_smoke_oneshot.ps1:80`) while the authored reverify receipt separates `EXT_LOAD=PASS` from `EXT_CLEANUP=FAIL`. Prefer the sealed `INTEG004_EXT_REVERIFY_RECEIPT.md` for gate language; cite runlog for `FORCE_KILL=1` measurement.

---

## INVESTIGATE roll-up (this worker)

| ID | Static lead (short) | Primary citation |
|----|---------------------|------------------|
| H01 | `AgentSession.cpp` not in Native-Ext link set; Ext sources completeness gate can skip target | CMake `:5547–5554`, `:3997–4120` |
| H02 | Dual extension host TUs / dual agent surfaces (AgentSession lib vs Win32IDE_Agent*) | CMake Ext sources vs agentic_backend |
| H03 | require() stub fallback; disabled `test_terminal` | `js_extension_host.cpp:2477`; CMake `:4129` |
| H04 | `RAWRXD_NATIVE_IDE_EXT` default OFF | CMake `:329` |
| H09 | Optional ggml/Deep2/security/hardening links | CMake `:4095–4111` |
| H10 | F:\ Build 3014 vs G:\ GGUF 3014 | CommandIDs / G:\ Win32IDE.cpp |
| H13 | Dual build ID spaces (3014 vs 5001+) | CommandIDs.h |
| H15 | G:\ accel 3014; absent on F:\ | G:\ Accelerators.cpp |
| H16/H18 | Terminal callback clear on teardown; posted UI msgs | Core.cpp `:5085+`; lifecycle `:429` |
| H27 | VS_UNICODE scrub path (historical/fixed — not new) | Commands.cpp `:567+` |
| H28 | Pipe drain-to-EOF patch present | TerminalManager.cpp `:416+` |
| H43–H52 | Ext wire present; clean quit hang under `--ext-quit` | ExtHostWire + EXT receipt |
| H51 | FORCE_KILL after bounded wait | INTEG004_EXT_REVERIFY_RECEIPT **CONFIRMED** |

## CONFIRMED (receipt-tied only)

1. **CC79 Problems UI FAIL** — historical controlling tip (`INTEG004_ACCEPTANCE_DISPOSITION.md`).
2. **integ_004 Problems UI PASS** — candidate SHA `47451F24…` (same + lineage).
3. **integ_004 EXT_CLEANUP FAIL / FORCE_KILL=1** — `INTEG004_EXT_REVERIFY_RECEIPT.md` + runlog.
4. **VS_UNICODE_OUTPUT** — CONFIRMED historical root cause on CC79 track; scrub/drain treated as candidate fix — **not** a newly discovered defect for this audit.

```
PROMOTE=0
TIP_MOVE_AUTHORIZED=0
A4F_IMMUTABLE=1
NOT_RUN != PASS
```
