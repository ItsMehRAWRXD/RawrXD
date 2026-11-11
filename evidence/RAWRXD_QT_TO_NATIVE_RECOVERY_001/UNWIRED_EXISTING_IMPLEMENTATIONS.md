# Unwired Existing Implementations

**Audit:** RAWRXD_QT_TO_NATIVE_RECOVERY_001  
**Source tree:** F:\rawrxd  
**Compiler:** MSVC 2026 (MSVC++2026) on Windows  
**Rule:** Source presence is NOT proof of functionality. An implementation is "unwired" when its .cpp/.h exists but is absent from every CMake build target's link graph, not registered in the IDE's command surface, or not reachable from the launched native executable.

---

## 1. CODEX CLI — codex_ide_integration.cpp (UNWIRED)

- **Path:** `F:\rawrxd\~dev\rawrxd\src\reverse_engineering\codex_ide_integration.cpp`
- **Size:** 314 lines
- **Language:** C++20, no Qt, no external dependencies
- **Purpose:** CLI + GUI entry point for RawrCodex multi-architecture decoder. Supports `decode`, `disasm`, `analyze`, `list-arch` commands for ARM64, MIPS32, RISC-V, x86, x64. Exports `Codex_Initialize`, `Codex_Shutdown`, `Codex_SetArchitecture`, `Codex_DecodeAtAddress` for IDE DLL integration.
- **Build status:** NOT referenced in any CMakeLists.txt in F:\rawrxd or F:\rawrxd\~dev\rawrxd. Not in the link graph of any target.
- **Executables present:** `F:\rawrxd\src\codex\build\rawrxd-codex.exe` and `rawrxd-codex-v2.exe` exist as pre-built binaries, but their source is not in the active build graph.
- **Required wiring:** Add `codex_ide_integration.cpp` to a CMake executable target (e.g. `rawrxd-codex`), link against `RawrXD-RE-Library`, register commands `rawrxd codex`, `/codex`, and route to Win32IDE command surface.
- **Blocker rank:** P0

---

## 2. RawrXD_Disasm_Kernel.asm (MISSING SOURCE — referenced but absent)

- **Referenced at:**
  - `F:\rawrxd\~dev\rawrxd\CMakeLists.txt` line 249: `file(GLOB ASM_SOURCES "src/asm/RawrXD_IPC_Dispatcher.asm" "src/asm/RawrXD_Disasm_Kernel.asm")`
  - `F:\rawrxd\~dev\rawrxd\CMakeLists.txt` line 259: `src/asm/RawrXD_Disasm_Kernel.asm` listed in `rawrxd` executable sources (guarded by `RAWRXD_BUILD_CLI=ON`)
  - `F:\rawrxd\audit\cmake_source_target_matrix.json` line 1907
  - `F:\rawrxd\audit\cmake_source_target_matrix.csv` line 121
  - `F:\rawrxd\build_pure_masm64_fixed.ps1` line 184
  - `F:\rawrxd\build_pure_masm64.ps1` line 178
- **On disk:** Does NOT exist. `F:\rawrxd\src\asm\` contains no `RawrXD_Disasm_Kernel.asm`.
- **Consequence:** The `rawrxd` executable target cannot link when `RAWRXD_BUILD_CLI=ON` because the assembler input is absent. MASM64 (`ml64.exe`) would fail with a missing file error.
- **Required action:** Locate the source (may be in a stash, backup, or worktree) or recreate it. Verify it assembles with `ml64.exe /c /Zi /Cx /W3`.
- **Blocker rank:** P0

---

## 3. LSP Client — lsp_client.cpp (QT-ONLY, no native equivalent)

- **Path:** `F:\rawrxd\src\lsp_client.cpp` (621 lines)
- **Dependencies:** `<QJsonDocument>`, `<QJsonArray>`, `<QJsonValue>`, `<QFileInfo>`, `<QDebug>`, `<QUrl>`, `<QCoreApplication>`, `QObject`, `QProcess`
- **Functionality:** Starts LSP server via QProcess, sends JSON-RPC initialize, handles completion/hover/definition/diagnostics/formatting capabilities, reads stdout via `readyReadStandardOutput`.
- **Native equivalent:** None exists. There is `F:\rawrxd\include\LanguageServerIntegration.h` (header only, contracts, no client implementation).
- **Build status:** Compiled only when Qt6 is found (`Qt6_FOUND`). Excluded from native dependency-free builds.
- **Required wiring:** Implement native JSON-RPC over anonymous pipes using Win32 `CreatePipe`/`CreateProcessW`. Parse JSON with vendored nlohmann/json (already vendored at `include/nlohmann/json.hpp`). Register with Win32IDE command surface and editor diagnostics.
- **Blocker rank:** P1

---

## 4. Terminal Pool — terminal_pool.cpp (QT-ONLY, partially unwired)

- **Path:** `F:\rawrxd\src\terminal_pool.cpp` (166 lines)
- **Dependencies:** `<QVBoxLayout>`, `<QHBoxLayout>`, `<QPushButton>`, `<QTabWidget>`, `<QTextEdit>`, `<QLineEdit>`, `<QProcess>`, `<QScrollBar>`, `<QDir>`, `QWidget`
- **Functionality:** Tabbed terminal containers, QProcess spawning `pwsh.exe`, input/output signal/slot wiring.
- **Native equivalent:** `F:\rawrxd\src\win32app\Win32TerminalManager.cpp` and `F:\rawrxd\src\win32app\Win32TerminalManager.h` exist. ConPTY-based terminal management is native.
- **Build status:** `terminal_pool.cpp` is Qt-only and excluded from native builds. `Win32TerminalManager.cpp` is in the `RawrXD-Win32IDE` target.
- **Required wiring:** Verify ConPTY lifecycle, signal handling, exit codes, and cancellation in `Win32TerminalManager.cpp`. The Qt `terminal_pool.cpp` should not be ported verbatim; behavior should be migrated into the native terminal manager.
- **Blocker rank:** P0

---

## 5. IDE Test Agent — IDETestAgent.h (NATIVE BUT DEFECTIVE — false positives)

- **Path:** `F:\rawrxd\src\win32app\IDETestAgent.h` (496 lines)
- **Defect:** `runTest()` marks a test as passed whenever the callback returns without throwing. Logging-only tests (`testPowerShellExecution`, `testModelInference`, `testAgenticCommands`, `testBreakpoints`, `testSyntaxHighlighting`, `testSidebar`, `testActivityBar`, `testSecondarySidebar`, `testTerminal`, `testTerminalOutput`, `testPowerShellPanel`, `testRawrXDModule`, `testDebugger`, `testWatchVariables`, `testFindDialog`, `testReplaceDialog`, `testSearchInFiles`, `testGitStatus`, `testGitOperations`, `testGGUFLoader`, `testModelInference`, `testCopilotChat`, `testAgenticCommands`, `testThemes`, `testSnippets`, `testClipboardHistory`, `testTransparentRenderer`, `testGPUText`) perform no assertions and are counted as PASS.
- **Additional defect:** Missing toolbar or explorer tree treated as warning, not failed assertion.
- **Build status:** Compiled into `test_runner` executable (if built).
- **Required wiring:** Replace logging-only callbacks with real assertions. Add timeout handling. Write results to a configurable path (not hardcoded `C:\RawrXD_IDE_TestResults.txt`). Never count no-throw as pass without verification.
- **Blocker rank:** P0

---

## 6. Test Runner — test_runner.cpp (NATIVE BUT DEFECTIVE)

- **Path:** `F:\rawrxd\src\win32app\test_runner.cpp` (139 lines)
- **Defects:**
  - Fixed `Sleep(500)` startup delay — does not establish asynchronous startup readiness.
  - Hardcoded output path `C:\RawrXD_IDE_TestResults.txt` — unnecessarily restrictive, not configurable.
  - No async readiness polling before running tests.
- **Build status:** Standalone executable, not in primary IDE target.
- **Required wiring:** Replace `Sleep(500)` with readiness polling (e.g., `IsWindowVisible` + message pump or named-pipe handshake). Make output path configurable via command-line argument or environment variable.
- **Blocker rank:** P0

---

## 7. PowerShell Integration — Win32IDE_PowerShell.cpp (NATIVE BUT DEFECTIVE)

- **Path:** `F:\rawrxd\src\win32app\Win32IDE_PowerShell.cpp` (918 lines)
- **Defects:**
  - Line 15: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "..."` — global execution-policy bypass for routine terminal functionality.
  - Line 43: `powershell.exe -NoProfile -Command "..."` — command string concatenation via `escapePowerShellString`.
  - Line 109: `Get-Module -ListAvailable | Select-Object Name | ConvertTo-Json` — JSON parsed with string search instead of proper parser.
- **Build status:** In `RawrXD-Win32IDE` target.
- **Required wiring:** Remove `-ExecutionPolicy Bypass`. Use parameter passing (`-Command` with `-ArgumentList`) or `Add-Type`/C# to avoid string concatenation. Parse JSON with nlohmann/json. Add ConPTY-based interactive terminal instead of fire-and-forget process creation.
- **Blocker rank:** P0

---

## 8. QtLogCompat.h — Qt logging shim in native code (NATIVE, wired but questionable)

- **Path:** `F:\rawrxd\src\win32app\QtLogCompat.h` (67 lines)
- **Purpose:** Routes `qDebug()`, `qInfo()`, `qWarning()`, `qCritical()`, `qError()` to `IDELogger` when Qt is not available.
- **Used by:** `Win32IDE_VSCodeUI.cpp` and `Win32IDE_Sidebar.cpp` (per header comments).
- **Build status:** Included in native build; compiles without Qt.
- **Assessment:** This is a compat shim, not a missing feature. It works but indicates Qt-era logging calls remain in native translation units. No action required unless Qt calls are removed and replaced with direct `IDELogger` calls.
- **Blocker rank:** P2 (cosmetic, no functional impact)

---

## 9. Qt-era source trees not in native build

The following directories contain Qt-era implementations that are NOT compiled into any native target:

| Directory | Qt-era content | Native equivalent | Build status |
|-----------|---------------|-------------------|--------------|
| `F:\rawrxd\src\qtapp\` | MainWindow_v5.cpp, ActivityBar*, TerminalWidget*, gpu_backend.cpp, codec.cpp, settings_manager.cpp, training_dialog.h, telemetry.h, model_queue.cpp, lsp_client.h | Win32IDE.cpp, Win32IDE_Sidebar.cpp, Win32TerminalManager.cpp, hardware_backend_selector.h, inflate_deflate_cpp.cpp, none | Excluded (Qt6 not found or RAWRXD_BUILD_WIN32IDE_QT=OFF) |
| `F:\rawrxd\src\terminal_pool.cpp` | QProcess terminal | Win32TerminalManager.cpp | Excluded (Qt-only) |
| `F:\rawrxd\src\lsp_client.cpp` | QProcess + Qt JSON LSP | None (native missing) | Excluded (Qt-only) |
| `F:\rawrxd\src\orchestration\`, `src\git\`, `src\terminal\` | Qt6-based RawrXDOrchestration, RawrXDGit, RawrXDTerminal | None native | Excluded when Qt6 not found (CMakeLists.txt lines 803-817) |
| `F:\rawrxd\src\paint\` | Qt paint shell | Not present | Excluded |

---

## 10. Reverse-engineering library — RawrXD-RE-Library (WIRED in ~dev tree only)

- **Path:** `F:\rawrxd\~dev\rawrxd\src\reverse_engineering\CMakeLists.txt`
- **Sources:** `pe_tools/re_tools.cpp`, `disassembler.cpp`, `pe_analyzer.cpp`, `decompiler.cpp`, `binary_patcher.cpp`
- **Headers:** `RawrCodex.hpp`, `RawrCompiler.hpp`, `RawrDumpBin.hpp`, `RawrReverseEngine.hpp`, `pe_tools/re_tools.h`
- **Target:** `RawrXD-RE-Library` (STATIC)
- **Build status:** Built in `F:\rawrxd\~dev\rawrxd\CMakeLists.txt`. Linked into `RawrXD-Win32IDE` at line 7538: `target_link_libraries(RawrXD-Win32IDE PRIVATE RawrXD-RE-Library)`.
- **Assessment:** Wired in the ~dev CMake tree. Not present in `F:\rawrxd\CMakeLists.txt` (the ModelLoader CMake). The main tree `F:\rawrxd\CMakeLists.txt` does not reference `RawrXD-RE-Library` or the reverse_engineering directory.
- **Required wiring:** Add `RawrXD-RE-Library` to `F:\rawrxd\CMakeLists.txt` and link into the production Win32 IDE target. Add codex command registration.
- **Blocker rank:** P0 (for main-tree production build)

---

## 11. HexMag Swarm (PARTIAL — cert targets exist, E2E unverified)

- **Path:** `F:\rawrxd\~dev\rawrxd\~dev\rawrxd\src\` (MASM-based swarm)
- **Cert targets:** `hexmag_repeat_tuner_cert`, `hexmag_ide_e2e_cert`, `hexmag_runtime_controller_cert` (in ~dev CMakeLists.txt lines 2338-2440)
- **Prerequisites:** `RAWR_HAS_MASM`, `~dev/rawrxd/tests/hexmag_repeat_tuner_cert.cpp`, MASM sources in `~dev/rawrxd/src/asm/` and `~dev/rawrxd/src/core/`
- **Build status:** Excluded when sources not found (message at line 2439: "HexMag cert targets EXCLUDED: required sources not found")
- **Required wiring:** Verify MASM sources exist; build cert targets; run E2E swarm test.
- **Blocker rank:** P2

---

## 12. Deep2 Native Inference (WIRED, GPU backend unverified)

- **Path:** `F:\rawrxd\src\deep2\`
- **Library:** `deep2_engine_lib` (in `F:\rawrxd\CMakeLists.txt` lines 2956-3196)
- **Executables:** `rawrxd_deep2_engine`, `deep2_agentic_loop`, `deep2_gpu_certify`, `deep2_parity_trace`, etc.
- **Build status:** Built when Vulkan SDK found. GPU backend (`VulkanCompute`) execution not yet certified on real device.
- **Required wiring:** Run `deep2_gpu_certify` on real hardware; verify token generation and GPU dispatch.
- **Blocker rank:** P1

---

## Summary of unwired/missing items

| # | Item | Status | Primary blocker | Rank |
|---|------|--------|-----------------|------|
| 1 | codex_ide_integration.cpp | UNWIRED — not in any CMake target | Add to build, link RE library, register CLI commands | P0 |
| 2 | RawrXD_Disasm_Kernel.asm | MISSING SOURCE — referenced but absent | Locate or recreate; verify MASM assembly | P0 |
| 3 | IDETestAgent.h | DEFECTIVE — false positives | Replace logging-only tests with assertions | P0 |
| 4 | test_runner.cpp | DEFECTIVE — fixed delay, hardcoded path | Readiness polling, configurable output | P0 |
| 5 | Win32IDE_PowerShell.cpp | DEFECTIVE — ExecutionPolicy Bypass, string concat | Remove bypass, safe arg passing, ConPTY | P0 |
| 6 | lsp_client.cpp | QT-ONLY — no native equivalent | Native JSON-RPC over pipes with nlohmann/json | P1 |
| 7 | terminal_pool.cpp | QT-ONLY — partially unwired | Verify Win32TerminalManager ConPTY behavior | P0 |
| 8 | RawrXD-RE-Library | NOT in F:\rawrxd\CMakeLists.txt | Add to main-tree CMake, link into Win32 IDE | P0 |
| 9 | Qt-era orchestration/git/terminal | EXCLUDED — Qt6 required | Native replacements needed or Qt6 build | P1 |
| 10 | HexMag Swarm | PARTIAL — cert targets excluded | Verify MASM sources, build and run certs | P2 |
