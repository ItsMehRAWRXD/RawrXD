# Remaining Work Ledger

**Audit:** RAWRXD_QT_TO_NATIVE_RECOVERY_001  
**Source tree:** F:\rawrxd  
**Compiler:** MSVC 2026 (MSVC++2026) on Windows  
**Generated:** 2026-10-23

---

## Ranking Criteria

- **P0:** Blocks production build, blocks CODEX CLI, or causes false certification (tests pass without verification). Must be fixed before any release-readiness claim.
- **P1:** Missing core IDE functionality (LSP, settings persistence, debugger, extensions, terminal ConPTY, GPU backend). Required for feature parity but does not block build.
- **P2:** Polish, cosmetic, or secondary features (telemetry, training UI, QtLogCompat cleanup, codec zlib replacement).

---

## P0 — Must fix before release

| ID | Item | Status | Evidence |
|----|------|--------|----------|
| P0-01 | CODEX CLI (codex_ide_integration.cpp) | **RESOLVED** | Added to F:\rawrxd\CMakeLists.txt rawrxd-codex target. Builds and runs: list-arch outputs 10 architectures; decode x64 90/CC/C3/EB05/E801000000/4889C8/488B01/488901/48B8... all SUCCESS; wrong arch returns INVALID_ARCH; unknown commands rejected. |
| P0-02 | RawrXD_Disasm_Kernel.asm | **RESOLVED (replaced)** | Missing asm replaced with native C++20 decoder at F:\rawrxd\src\asm\RawrXD_Disasm_Kernel.hpp/.cpp. 25/25 smoke tests PASS including previously-failing 0x83 Group 1 (sub rsp,0x20) and x86 architecture admission. Implements ReferenceDecoder_Decode (previously undefined dllexport symbol). |
| P0-03 | IDETestAgent.h false positives | **RESOLVED** | runTest() now requires std::function<bool()> return — logging-only void callbacks no longer compile. Added TEST_ASSERT/TEST_ASSERT_EQUAL/TEST_ASSERT_NOT_NULL macros. 20+ logging-only tests replaced with real assertions. |
| P0-04 | test_runner.cpp defects | **RESOLVED** | Replaced Sleep(500) blind wait with waitForWindowReady() polling (10s max, 100ms intervals). Replaced hardcoded C:\RawrXD_IDE_TestResults.txt with configurable --output path. |
| P0-05 | Win32IDE_PowerShell.cpp defects | **RESOLVED** | Removed -ExecutionPolicy Bypass. executePowerShellCommand now uses -EncodedCommand (base64) transport. getPowerShellModules() parses JSON via RawrXD::Json (zero-dependency json_mini.h) instead of string search. Builds cleanly in RawrXD-Win32IDE-Native. |
| P0-06 | RawrXD-RE-Library not in main-tree CMake | **RESOLVED** | Added to F:\rawrxd\CMakeLists.txt. Builds cleanly. Linked into rawrxd-codex executable. |
| P0-07 | CODEX CLI-to-IDE routing | UNRESOLVED | No command registration for CODEX in Win32IDE command surface. No menu items, no Ctrl+Shift+C shortcut. Needs Win32IDE_Commands.cpp registration. |
| P0-08 | Symbol index buildIndex (empty no-op) | UNRESOLVED | SymbolIndex::buildIndex() is empty in checked-in source. Needs implementation + findByName verification. |
| P0-09 | Extension hosts (false-success) | UNRESOLVED | Extension hosts in ~dev tree return success without executing commands. Need real implementation or explicit NOT_IMPLEMENTED. |
| P0-10 | Model loader (fake GGUF loader) | UNRESOLVED | Fake loader returns !path.empty() without opening file. Need real Deep2 GGUF loader connection. |

---

## P1 — Required for feature parity

| ID | Item | Exact missing wiring / functionality | Source path | Build target | Evidence required |
|----|------|--------------------------------------|-------------|--------------|-------------------|
| P1-01 | Native LSP client | No native JSON-RPC over pipes. `lsp_client.cpp` is Qt-only (QProcess, QJsonDocument). | `F:\rawrxd\src\lsp_client.cpp` | None (Qt-only) | Implement `NativeLSPClient` with Win32 pipes + nlohmann/json; launch real LSP server; receive completion/diagnostics |
| P1-02 | Settings persistence | No native settings store with restart persistence. Qt `settings_manager.cpp` exists but not connected. | `F:\rawrxd\src\qtapp\settings_manager.cpp` | None | `SettingsStore::Set`/`Save`; restart process; `Load` returns same value |
| P1-03 | Debugger variable inspection | `Win32IDE_Debugger.cpp` backend exists but not connected to native debug panel. Breakpoint hit + variable read not certified. | `F:\rawrxd\src\win32app\Win32IDE_Debugger.cpp` | RawrXD-Win32IDE | Launch debug target; set breakpoint; hit it; inspect variable value in watch panel |
| P1-04 | Terminal ConPTY verification | `Win32TerminalManager.cpp` exists but ConPTY lifecycle, signals, exit codes not certified. | `F:\rawrxd\src\win32app\Win32TerminalManager.cpp` | RawrXD-Win32IDE | Launch `pwsh.exe` in ConPTY; run command; capture output; get exit code; send Ctrl+C |
| P1-05 | Extension activation | `Win32IDE_ExtensionCert.cpp` exists but false-success hosts in ~dev tree return success without executing. Real extension load/execute not certified. | `F:\rawrxd\src\win32app\Win32IDE_ExtensionCert.cpp` | RawrXD-Win32IDE | Load real extension; register command; execute; observe result. Unknown command returns explicit failure. |
| P1-06 | GPU backend selector | `hardware_backend_selector.h` exists but device selection and runtime routing unverified on real hardware. | `F:\rawrxd\src\hardware_backend_selector.h` | RawrXD-Win32IDE | Select AMD GPU; verify inference routes to Vulkan/HIP backend; CPU fallback works |
| P1-07 | Symbol index buildIndex | `SymbolIndex::buildIndex()` is empty (no-op) in checked-in source (GitHub-referenced). | `F:\rawrxd\~dev\rawrxd\src\core\symbol_index_impl.cpp` | None | Implement buildIndex; verify `findByName` returns indexed symbol |

---

## P2 — Polish / secondary

| ID | Item | Exact missing wiring / functionality | Source path | Build target | Evidence required |
|----|------|--------------------------------------|-------------|--------------|-------------------|
| P2-01 | QtLogCompat cleanup | Qt logging calls remain in native translation units (`Win32IDE_VSCodeUI.cpp`, `Win32IDE_Sidebar.cpp`). Replace with direct `IDELogger` calls. | `F:\rawrxd\src\win32app\QtLogCompat.h` | RawrXD-Win32IDE | Build without Qt6; no qInfo/qDebug identifier errors; logs appear in RawrXD_IDE.log |
| P2-02 | Codec/zlib replacement | Qt `codec.cpp` uses Qt+zlib. Confirm MASM deflate (`inflate_deflate_cpp.cpp`) replaces it in production. | `F:\rawrxd\src\qtapp\codec.cpp` | brutal_compression_lib | Build without zlib; compress/decompress round-trip byte-identical |
| P2-03 | Telemetry preferences | Qt telemetry dialog exists; native local-only settings not implemented. | `F:\rawrxd\src\qtapp\telemetry.h` | None | Implement local-only telemetry controls; verify settings persist |
| P2-04 | Training dialog | Qt training dialog exists; native Win32 equivalent not ported. | `F:\rawrxd\src\qtapp\training_dialog.h` | None | Implement native training dialog; verify validation |
| P2-05 | Model download UI | Qt model download UI exists; native WinHTTP streaming with progress/cancellation not ported. | `F:\rawrxd\src\qtapp\model_queue.cpp` | None | Implement native model download; verify progress bar and cancellation |

---

## Reuse — No work required (already native + built + in production target)

| Item | Source path | Build target | Status |
|------|-------------|--------------|--------|
| Win32IDE main window + editor | `F:\rawrxd\src\win32app\Win32IDE.cpp` | RawrXD-Win32IDE | Built, runtime unverified |
| Activity Bar + 5 sidebar views | `F:\rawrxd\src\win32app\Win32IDE_Sidebar.cpp` | RawrXD-Win32IDE | Built, runtime unverified |
| streaming_gguf_loader (native GGUF) | `F:\rawrxd\src\streaming_gguf_loader.cpp` | deep2_engine_lib | Built, runtime unverified |
| QtLogCompat shim | `F:\rawrxd\src\win32app\QtLogCompat.h` | RawrXD-Win32IDE | Built and functional |
| rawrxd_snapshot library | `F:\rawrxd\src\snapshot\` | rawrxd_snapshot | Built, restart persistence unverified |
| rawrxd_workflow (WebView2) | `F:\rawrxd\src\workflow\` | rawrxd_workflow | Built, rendering unverified |
| Native C++ regex (<regex>) | `F:\rawrxd\src\win32app\Win32IDE.cpp` | RawrXD-Win32IDE | Built |
| WinHTTP cloud_api_client | `F:\rawrxd\src\cloud_api_client.cpp` | deep2_agentic_loop | Built |

---

## Obsolete / Do not port

| Item | Reason |
|------|--------|
| `F:\rawrxd\src\qtapp\MainWindow_v5.cpp` | Duplicate of native `Win32IDE.cpp`. Do not port Qt classes; port behavior only. |
| `F:\rawrxd\src\qtapp\ActivityBar.cpp` | Duplicate of native `Win32IDE_Sidebar.cpp`. |
| `F:\rawrxd\src\qtapp\TerminalWidget.cpp` | Duplicate of native `Win32TerminalManager.cpp`. |
| `F:\rawrxd\src\qtapp\codec.cpp` | Uses Qt+zlib; native MASM deflate exists. |
| `F:\rawrxd\src\qtapp\training_dialog.h` | Qt-only; port behavior via Win32 controls if needed (P2). |
| `F:\rawrxd\src\qtapp\telemetry.h` | Qt-only; local-only settings preferred (P2). |
| Qt-era orchestration/git/terminal (`src/orchestration`, `src/git`, `src/terminal`) | Qt6-based; excluded from native builds. Native replacements needed or Qt6 build. |

---

## Unresolved items with exact requirements

| ID | Item | Exact implementation requirement | Exact verification requirement |
|----|------|----------------------------------|-------------------------------|
| UNR-001 | RawrXD_Disasm_Kernel.asm | Recreate MASM64 disassembly kernel source at `F:\rawrxd\src\asm\RawrXD_Disasm_Kernel.asm` | `ml64.exe /c /Zi /Cx /W3` produces `.obj` with zero errors |
| UNR-002 | codex_ide_integration.cpp wiring | Add to `F:\rawrxd\CMakeLists.txt` as `rawrxd-codex` executable; link `RawrXD-RE-Library`; register `rawrxd codex` / `/codex` commands | `rawrxd-codex.exe list-arch` outputs architectures; `rawrxd-codex.exe decode x64 4889C8` outputs `mov rax, rcx` |
| UNR-003 | IDETestAgent.h assertions | Rewrite `runTest()` to require explicit bool return or throw; replace 20+ logging-only tests with real assertions | `test_runner.exe --headless` runs; zero tests pass solely on no-throw; every test has verifiable pass/fail evidence |
| UNR-004 | PowerShell safe execution | Remove `-ExecutionPolicy Bypass`; replace string concatenation with parameter passing; parse JSON with nlohmann/json | `executePowerShellScript` runs without bypass; arguments with spaces pass correctly; `getPowerShellModules()` returns valid JSON-parsed module list |
| UNR-005 | Native LSP client | Implement JSON-RPC over anonymous pipes using Win32 `CreatePipe`/`CreateProcessW`; nlohmann/json for parsing | Launch clangd/test server; send `initialize`; receive response; request completion; receive items — all without Qt6 |
| UNR-006 | Settings restart persistence | Implement `SettingsStore` with JSON file at `%LOCALAPPDATA%\RawrXD\settings.json`; connect to IDE settings panel | Change setting; restart RawrXD; verify setting survives restart |
| UNR-007 | Extension host truthfulness | Remove false-success `ExecuteCommand`/`ExecuteScript`/`LoadExtension` in ~dev extension hosts; connect real implementation | `ExecuteCommand("nonexistent")` returns `false`; registered command executes and produces observable result |

---

## Final release-readiness verdict

**VERDICT: BLOCKED**

The production native executable cannot be certified as release-ready until all P0 blockers are resolved:
1. `codex_ide_integration.cpp` must be wired into the CMake build graph and produce a working `rawrxd-codex.exe`.
2. `RawrXD_Disasm_Kernel.asm` must be located or recreated so the `rawrxd` CLI target can link.
3. `IDETestAgent.h` must be fixed so logging-only tests can no longer award false passes.
4. `test_runner.cpp` must use readiness polling instead of `Sleep(500)` and a configurable output path.
5. `Win32IDE_PowerShell.cpp` must remove `-ExecutionPolicy Bypass` and use safe argument passing.
6. `RawrXD-RE-Library` must be added to `F:\rawrxd\CMakeLists.txt` and linked into the production Win32 IDE.

Until each blocker has a real execution receipt (not a log line), no release-readiness claim can be truthfully made.
