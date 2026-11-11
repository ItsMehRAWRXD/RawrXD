# INTEG_004 — RawrXD Win32 Native IDE Hidden Gap Audit

```text
AUDIT_ID=INTEG_004_HIDDEN_AUDIT_20261109
METHOD=STATIC_REVERSE_ENGINEERING
DISPOSITION=INVESTIGATE_FINDINGS_ONLY
PROMOTE=0
TIP_CLIMB=HOLD
NOT_RUN != PASS
SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS
DATE=2026-11-09
SCOPE_ROOTS=
  g:\~dev\rawrxd (non-models)
  g:\~dev\native-ide
  g:\~dev\src (CMake dual-tree compare)
  g:\~dev\ide
  g:\~dev\extension-host-system
PRODUCT_TARGET_PREFERRED=RawrXD-Win32IDE (rxdn_* build trees)
EXCLUDED=rawrxd/models symlink loops
```

## Tag legend

| Tag | Meaning |
|-----|---------|
| **CONFIRMED** | Static evidence shows defect/gap with file:line citations; threatens product-final E2E without needing runtime. |
| **UNVERIFIED** | Strong static signal, but runtime/link-admission ownership not proven in this pass. |
| **INVESTIGATE** | Ambiguous dual path / optional flag / orphan TU — needs owner trace before treating as defect. |

---

## Executive: Top 20 highest-risk findings

Ordered by threat to Issue-#49-style product-final E2E (build → diagnostics → navigate → agent/extension/debug/compiler paths).

### 1. CONFIRMED — Problems NM_DBLCLK dispatches to wrong navigation owner (`goToProblem` / `m_problems`)

- **Why it threatens acceptance:** Build/LSP feed `ProblemsAggregator` → filtered `m_problemsViewCache`. Product double-click / panel activate paths still call `goToProblem(idx)` against legacy `m_problems`, so caret navigation can no-op or open the wrong entry after a real build.
- **Evidence:**
  - `rawrxd/src/win32app/Win32IDE_Core.cpp:1239-1245` — `NM_DBLCLK` / `LVN_ITEMACTIVATE` → `goToProblem(idx)`
  - `rawrxd/src/win32app/Win32IDE_Core.cpp:5587-5596`, `:5643-5649` — `IDC_PANEL_PROBLEMS_LIST` / `IDC_PROBLEMS_LISTVIEW` → `goToProblem`
  - `rawrxd/src/win32app/Win32IDE_VSCodeUI.cpp:731-753` — `goToProblem` indexes `m_problems` only
  - `rawrxd/src/win32app/Win32IDE_ProblemsPanel.cpp:265-360` — product refresh uses aggregator → `m_problemsViewCache`; activate uses `onProblemsItemActivate` → `navigateToFileLine`
  - `rawrxd/src/win32app/Win32IDE_BuildRunner.cpp:71`, `:118` — build errors go to aggregator, not `m_problems`

### 2. CONFIRMED — Dual Problems ListView creators overwrite `m_hwndProblemsListView`

- **Why:** Two creators assign the same member (`VSCodeUI` panel vs `initProblemsPanel`). Last init wins; NM_NOTIFY vs subclass paths diverge; Issue #49 “dblclk opens file:line” becomes non-deterministic by startup order.
- **Evidence:**
  - `Win32IDE_VSCodeUI.cpp:546-551` — creates ListView under `IDC_PANEL_PROBLEMS_LIST` into `m_hwndProblemsListView`
  - `Win32IDE_ProblemsPanel.cpp:226-251` — recreates ListView under `IDC_PROBLEMS_LISTVIEW` into same member + subclass
  - `Win32IDE_SidebarPanels.cpp:7-18` — third Problems list (`m_hwndProblemsList`) with same command id `1312` (**admission UNVERIFIED** in `rawrxd/CMakeLists.txt`)

### 3. CONFIRMED — `goToProblem` bypasses document/tab open path

- **Why:** Even when `m_problems` is populated, navigation uses raw `ifstream` + `SetWindowTextA` without `openFile` / tab manager — dirty state, encoding, and multi-tab E2E break.
- **Evidence:** `Win32IDE_VSCodeUI.cpp:737-746` vs product `navigateToFileLine` in `Win32IDE_SemanticPanel.cpp:67-76` (`openFile` + `EM_EXSETSEL`).

### 4. CONFIRMED — BuildRunner: no cancel, no job object, no process-tree kill

- **Why:** Detached `std::thread` + `CreateProcessA("cmd /c …")` with no stored `PROCESS_INFORMATION`, no `CreateJobObject`, no cancel API. Stop-build / shutdown leaves orphan compiler trees — fails lifecycle E2E and can corrupt subsequent diagnostics.
- **Evidence:** `Win32IDE_BuildRunner.cpp:70-127` (spawn `:94-95`, detach `:127`). Workspace grep: no `VS_UNICODE_OUTPUT` / `TerminateProcess` / `JobObject` in this TU.

### 5. CONFIRMED — Zero `VS_UNICODE_OUTPUT` handling in `rawrxd/src`

- **Why:** MSVC redirects structured diagnostics when `VS_UNICODE_OUTPUT` is set; without handling, pipe parsers miss/garble cl.exe output → empty/wrong Problems → false E2E FAIL or silent miss.
- **Evidence:** workspace grep `VS_UNICODE_OUTPUT` under `rawrxd/src` → **no matches**. BuildRunner / Tasks use ANSI pipes only (`CreateProcessA` + `ReadFile` byte stream).

### 6. CONFIRMED — Cross-thread UI write from BuildRunner completion path

- **Why:** Worker thread calls `refreshProblemsView()` which mutates ListView / status bar HWNDs directly (not via `postOutputPanelSafe` / `PostMessage`). Classic HWND race / teardown UAF under cancel/close during build.
- **Evidence:**
  - `Win32IDE_BuildRunner.cpp:126` — `refreshProblemsView()` on worker
  - `Win32IDE_ProblemsPanel.cpp:265-344` — direct `ListView_*` / `SendMessageW(m_hwndStatusBar, …)`
  - Contrast safe path: `Win32IDE.cpp:8542-8558` — `postOutputPanelSafe` → `WM_IDE_OUTPUT_APPEND_SAFE`

### 7. CONFIRMED — `/FORCE:MULTIPLE` required on product Win32IDE link

- **Why:** Duplicate symbol resolution is link-order lottery. Command handlers from `ssot_handlers` vs `auto_feature_registry` can silently bind the wrong body — menu shows live, handler is stub/other lane. Blocks trustworthy product-final certification.
- **Evidence:**
  - `rawrxd/CMakeLists.txt:6744-6748` — documents intentional duplicate handlers
  - `rawrxd/CMakeLists.txt:7622` — `"/FORCE:MULTIPLE"` on `RawrXD-Win32IDE`
  - Duplicate TU admission: `Win32IDE_Settings.cpp` + `Win32IDE_TaskRunner.cpp` listed twice (`:5744-5745` and `:5799-5800`)

### 8. CONFIRMED — `RAWRXD_BUILD_WIN32IDE` defaults OFF in `rawrxd/CMakeLists.txt`

- **Why:** Default configure can ship RawrEngine/Gold without the GUI product target unless rxdn scripts force the option. Dual tree `g:\~dev\src\CMakeLists.txt:210` defaults **ON** — admission drift between trees.
- **Evidence:** `rawrxd/CMakeLists.txt:232` `option(... OFF)`; `src/CMakeLists.txt:210` `option(... ON)`.

### 9. CONFIRMED — GATED_OMIT agentic/debug bridge TUs excluded from Win32IDE

- **Why:** Menu/feature surface may still advertise LoRA / logpoint / agent-bridge init while product link omits owners → empty or unresolved behavior under agentic E2E.
- **Evidence:** `rawrxd/CMakeLists.txt:5721-5730` comments omit:
  - `Win32IDE_AgenticFeatures.cpp`
  - `Win32IDE_LoRAKernelBridge.cpp`
  - `Win32IDE_AgentBridge_Init.cpp`
  - `Win32IDE_LogpointBridge.cpp`
  - `Win32IDE_SidebarBridge.cpp`
- Related fail-closed stubs still present on disk: `Win32IDE_LoRAKernelBridge.cpp`, `Win32IDE_AgenticFeatures.cpp` (fake-success removed → return -1).

### 10. CONFIRMED — Extension Host compile-time disabled + marketplace install fiction-closed

- **Why:** Extension E2E (Issue #49 family: install → activate → command) cannot pass on product path while host gate is `false` and VSIX extract returns false after download.
- **Evidence:**
  - `FeatureRegistry.hpp:53-55` — `IsExtensionHostEnabled() { return false; }` “STUB implementation only”
  - `ExtensionHost_Discovery.cpp:334-346` — “Extract VSIX — not implemented”; `return false` / FEATURE_FICTION

### 11. CONFIRMED — TaskManager marks `result.success = true` regardless of process exit code

- **Why:** Failed builds/tests report success at task layer if `CreateProcess` succeeded — fake-success adjacent; problems panel may populate while task UI shows pass.
- **Evidence:** `Win32IDE_Tasks.cpp:629-636` — reads `exitCode` then unconditionally `result.success = true`.

### 12. CONFIRMED — Task execute path: no cancel / TerminateProcess / JobObject

- **Why:** Same lifecycle class as BuildRunner; long tasks cannot be stopped with process-tree kill. Terminal path has job objects (`Win32TerminalManager.cpp:76-91`) — tasks/build do not.
- **Evidence:** `Win32IDE_Tasks.cpp:606-635`; grep of TU for `TerminateProcess`/`JobObject`/`cancel` → no matches.

### 13. CONFIRMED — `Win32IDE_Build.cpp` stop/toolchain path not admitted in `rawrxd/CMakeLists.txt`

- **Why:** `onBuildStop` / `m_toolchain->stopBuild()` exist in source (`Win32IDE_Build.cpp:317-321`) and accelerators define `IDM_BUILD_STOP` (`Win32IDE_Accelerators.cpp:37`), but `Win32IDE_Build.cpp` is **absent** from `rawrxd/CMakeLists.txt` admission. Product stop-build may be unbound while BuildRunner cannot cancel.
- **Evidence:** CMake grep `Win32IDE_Build\.cpp` in `rawrxd/CMakeLists.txt` → no matches; BuildRunner **is** admitted (`:6325`).

### 14. CONFIRMED — Feature fiction command handlers still in tree (Transcendence/Vulkan/MCP/…)

- **Why:** If any menu/palette ID still routes into these handlers, user-visible commands return FEATURE_FICTION failures — acceptance false-negative or silent “worked” depending on UI.
- **Evidence:** `Win32IDE_CommandHandlers.cpp:27-106` — multiple `NOT_PRODUCT_PATH=1 FEATURE_FICTION=1` returns. Note: `rawrxd/CMakeLists.txt:7136` says this TU removed from Win32IDE (ownership → `rawrengine_command_handlers.cpp`) — **admission status INVESTIGATE for which binary still links it**.

### 15. CONFIRMED — StubFiction cite-force TUs linked into Win32IDE

- **Why:** Product binary intentionally embeds FEATURE_FICTION string cites / healer touches for MAP audits — not a runtime feature, but proves stub residual is still in release link graph (cert noise; risk of OPTIMIZE-in of stub paths).
- **Evidence:** `rawrxd/CMakeLists.txt:5737-5738`; `Win32IDE_StubFictionCiteForce.cpp:1-28`.

### 16. CONFIRMED — `g_pProblemsIDE` set, never cleared on destroy

- **Why:** Problems panel timer (`WM_TIMER`) and subclass dblclk call through static `g_pProblemsIDE` after shell teardown → UAF / stale callback if timer or late notify fires during destroy races with BuildRunner refresh.
- **Evidence:**
  - Set: `Win32IDE_ProblemsPanel.cpp:188`
  - Timer use: `:79-88`
  - Subclass use: `:172-178`
  - `onDestroy` in `Win32IDE_Core.cpp:4920+` — no `g_pProblemsIDE = nullptr` found; `g_pMainIDE` likewise only assigned in `Win32IDE.cpp:875`

### 17. CONFIRMED — Detached-thread shutdown is poll-only with known TODO

- **Why:** `onDestroy` waits ≤3s on `m_activeDetachedThreads` then continues; BuildRunner thread is `.detach()`’d and may still call into `this` / HWND after destroy → lifecycle fail under Issue #49 soak.
- **Evidence:** `Win32IDE_Core.cpp:4933-4942` TODO; BuildRunner `:127` `.detach()`.

### 18. UNVERIFIED — `Win32IDE_MissingActions` explorer/git actions fail-closed early-return

- **Why:** Delete/rename/discard are no-ops (FEATURE_FICTION) if linked and menu-wired — explorer E2E break. Admitted in `src/CMakeLists.txt:4457`; **not** found in `rawrxd/CMakeLists.txt` this pass.
- **Evidence:** `Win32IDE_MissingActions.cpp:14-20`, `:29-35`, `:125-131`. Tag **UNVERIFIED** for rawrxd product link; **CONFIRMED** fiction if `src/` tree builds rxdn.

### 19. INVESTIGATE — `native-ide/` is a separate minimal product, not RawrXD-Win32IDE

- **Why:** `g:\~dev\native-ide` builds `native_ide.exe` with tiny C core + Vulkan bridge forced CPU fallback (`VKBRIDGE_USE_RAWRXD_BACKEND=0`). Not the Win32IDE command/problems/agent graph. Risk: wrong binary certified as “native IDE.”
- **Evidence:** `native-ide/CMakeLists.txt:29`, `:52-61`.

### 20. INVESTIGATE — Fallback / missing-handler stub lanes still optional

- **Why:** `RAWRXD_ENABLE_MISSING_HANDLER_STUBS` and non-strip `_RAWRXD_WIN32IDE_FALLBACK_UNITS` can reintroduce stub wiring; production strip conflicts are FATAL only when both flags clash — misconfigure can ship stubs.
- **Evidence:** `rawrxd/CMakeLists.txt:236`, `:3059-3065`, `:6791-6817`, `:8087+`.

---

## Category deep notes

### A. BUILD GRAPH

| ID | Tag | Finding | Cite |
|----|-----|---------|------|
| B1 | CONFIRMED | Win32IDE default OFF in rawrxd CMake | `CMakeLists.txt:232` |
| B2 | CONFIRMED | Dual CMake trees disagree on default ON/OFF | `rawrxd/:232` vs `src/:210` |
| B3 | CONFIRMED | `/FORCE:MULTIPLE` + documented duplicate handlers | `:6744-6748`, `:7622` |
| B4 | CONFIRMED | Duplicate Settings/TaskRunner source entries | `:5744-5745`, `:5799-5800` |
| B5 | CONFIRMED | GATED_OMIT agentic/LoRA/logpoint/sidebar bridges | `:5721-5730` |
| B6 | CONFIRMED | `Win32IDE_Window.cpp` removed to avoid duplicate WindowProc | `:5698-5699` |
| B7 | CONFIRMED | `Win32IDE_Build.cpp` not in rawrxd admission; BuildRunner is | grep + `:6325` |
| B8 | CONFIRMED | StubFiction cite TUs admitted | `:5737-5738` |
| B9 | INVESTIGATE | Fallback units append when strip OFF | `:6791-6817` |
| B10 | INVESTIGATE | `FullAgenticIDE.cpp` listed near GATED_OMIT block | `:5739` |

### B. STUB / FALLBACK

| ID | Tag | Finding | Cite |
|----|-----|---------|------|
| S1 | CONFIRMED | Extension host gated false | `FeatureRegistry.hpp:53-55` |
| S2 | CONFIRMED | VSIX install fail-closed after download | `ExtensionHost_Discovery.cpp:334-346` |
| S3 | CONFIRMED | MissingActions fiction early-return | `Win32IDE_MissingActions.cpp` |
| S4 | CONFIRMED | CommandHandlers FEATURE_FICTION cluster | `Win32IDE_CommandHandlers.cpp:27-106` |
| S5 | CONFIRMED | Remote control stub always blocked | `CommandRemoteStub.h:17-21` |
| S6 | CONFIRMED | Omega/Autonomous feature constexpr false | `FeatureRegistry.hpp:49-71` |
| S7 | UNVERIFIED | IDENTITY=0 style numeric fallbacks — only Vulkan component-mapping comment hit in win32app | `VulkanRenderer.cpp:584` (not IDE path) |

### C. COMMAND GRAPH

| ID | Tag | Finding | Cite |
|----|-----|---------|------|
| C1 | CONFIRMED | FORCE:MULTIPLE can bind wrong handler body | CMake `:6744-6748` |
| C2 | CONFIRMED | Build stop accelerator may lack admitted handler TU | `Win32IDE_Build.cpp` not in CMake; `IDM_BUILD_STOP` in Accelerators |
| C3 | INVESTIGATE | `Win32IDE_CommandHandlers.cpp` removed per comment — verify map for residual IDs | `:7136` |
| C4 | UNVERIFIED | Palette/menu density vs GATED_OMIT features | menus in `Win32IDE.cpp` vs omitted TUs |

### D. LIFECYCLE

| ID | Tag | Finding | Cite |
|----|-----|---------|------|
| L1 | CONFIRMED | BuildRunner no cancel / no job | `Win32IDE_BuildRunner.cpp` |
| L2 | CONFIRMED | Tasks no cancel / no job | `Win32IDE_Tasks.cpp` |
| L3 | CONFIRMED | Cross-thread ListView refresh | BuildRunner `:126` + ProblemsPanel `:265+` |
| L4 | CONFIRMED | No VS_UNICODE_OUTPUT | repo grep empty |
| L5 | CONFIRMED | `g_pProblemsIDE` stale risk | ProblemsPanel + onDestroy |
| L6 | CONFIRMED | Detached thread poll shutdown TODO | Core `:4933-4942` |
| L7 | UNVERIFIED | Terminal job-kill path OK relative to build — parity gap only | `Win32TerminalManager.cpp:76-91`, `:261` |

### E. PROBLEMS NAVIGATION

| ID | Tag | Finding | Cite |
|----|-----|---------|------|
| P1 | CONFIRMED | NM_DBLCLK → `goToProblem` / `m_problems` | Core `:1239-1245` |
| P2 | CONFIRMED | Subclass dblclk → `onProblemsItemActivate` / cache | ProblemsPanel `:172-178`, `:347-360` |
| P3 | CONFIRMED | Dual ListView HWND ownership | VSCodeUI `:547` vs ProblemsPanel `:226` |
| P4 | CONFIRMED | Aggregator vs `m_problems` split | BuildRunner vs VSCodeUI `addProblem` |
| P5 | CONFIRMED | `goToProblem` skips `openFile` | VSCodeUI `:737-746` |

---

## Non-findings / explicitly not elevated

- Many historical “was fake success” comments show prior sweeps already fail-closed (LoRA, NeuralBridge, ProductionReadyGate) — **not** current fake-PASS unless still linked on product path.
- `native-ide` arena `platform_free` no-op is by design (README) — out of RawrXD-Win32IDE scope.
- `extension-host-system` TS tree: no stub/TODO hits in this pass’s shallow grep — does not override C++ `IsExtensionHostEnabled()==false`.

---

## Recommended next gates (still INVESTIGATE — do not invent PASS)

1. MAP/`dumpbin` on tip `RawrXD-Win32IDE.exe`: which Problems/Build/MissingActions/CommandHandlers symbols actually bind under `/FORCE:MULTIPLE`.
2. Runtime single-path: force one Problems ListView owner; route all activate → `onProblemsItemActivate` / `navigateToFileLine`.
3. Build/Task: job object + cancel + UI-thread marshal + `VS_UNICODE_OUTPUT` policy.
4. Lock single CMake root + `RAWRXD_BUILD_WIN32IDE=ON` for rxdn product configures.
5. Clear `g_pProblemsIDE` / `g_pMainIDE` on destroy; track BuildRunner thread joinable handle.

```text
AUDIT_COMPLETE=1
FINDINGS_TOP20=20
CONFIRMED_DOMINANT=1
PROMOTE=0
CERTIFIED=0
PERFECT=0
```
