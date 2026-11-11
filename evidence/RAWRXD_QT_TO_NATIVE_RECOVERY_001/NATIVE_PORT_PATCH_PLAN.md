# Native Port Patch Plan

**Audit:** RAWRXD_QT_TO_NATIVE_RECOVERY_001  
**Source tree:** F:\rawrxd  
**Compiler:** MSVC 2026 (MSVC++2026) on Windows  
**Objective:** Port Qt-era feature behavior into the native Win32/C++20 IDE without Qt or new third-party dependencies.  
**Rule:** Port behavior, not Qt classes. Reuse existing RawrXD implementations before writing replacements. Never claim a feature is working based solely on source presence.

---

## Patch Plan Overview

| Patch ID | Target | Scope | Depends On | Rank | Est. Effort |
|----------|--------|-------|------------|------|-------------|
| PATCH-001 | CMake build graph | Add codex_ide_integration.cpp + RawrXD-RE-Library to F:\rawrxd\CMakeLists.txt | PATCH-002 | P0 | Small |
| PATCH-002 | RawrXD_Disasm_Kernel.asm | Locate or recreate missing MASM source | None | P0 | Medium |
| PATCH-003 | IDETestAgent.h | Replace logging-only tests with real assertions | PATCH-004 | P0 | Medium |
| PATCH-004 | test_runner.cpp | Replace Sleep(500) with readiness polling; configurable output path | None | P0 | Small |
| PATCH-005 | Win32IDE_PowerShell.cpp | Remove -ExecutionPolicy Bypass; safe argument passing; ConPTY | None | P0 | Medium |
| PATCH-006 | LSP client | Native JSON-RPC over pipes (replace Qt lsp_client.cpp) | None | P1 | Large |
| PATCH-007 | Terminal | Verify Win32TerminalManager ConPTY lifecycle, signals, exit codes | PATCH-005 | P0 | Medium |
| PATCH-008 | Settings persistence | Native JSON config store; restart persistence test | None | P1 | Medium |
| PATCH-009 | Debugger variable inspection | Connect Win32IDE_Debugger.cpp backend to native panel | None | P1 | Medium |
| PATCH-010 | Extensions | Verify activation, commands, marketplace; remove false-success hosts | None | P1 | Medium |
| PATCH-011 | GGUF streaming | Confirm native streaming_gguf_loader.cpp is wired and tested | None | P0 | Small |
| PATCH-012 | GPU backend selector | Verify actual device selection and runtime routing | None | P1 | Medium |
| PATCH-013 | CODEX CLI-to-IDE routing | Register rawrxd codex / /codex commands in Win32IDE command surface | PATCH-001 | P0 | Medium |
| PATCH-014 | QtLogCompat shim | Replace Qt logging calls with direct IDELogger calls | None | P2 | Small |
| PATCH-015 | Codec/zlib replacement | Confirm MASM deflate replaces Qt/zlib in production | None | P2 | Medium |
| PATCH-016 | Symbol index buildIndex | Fix empty SymbolIndex::buildIndex (if present locally) | None | P0 | Small |
| PATCH-017 | Extension hosts | Remove false-success ExecuteCommand/ExecuteScript | None | P0 | Small |
| PATCH-018 | Model loader | Remove fake GGUF loader (if present locally); connect real Deep2 loader | None | P0 | Small |

---

## PATCH-001: CMake build graph — CODEX CLI + RE library

**File:** `F:\rawrxd\CMakeLists.txt`

**Change:** Add the CODEX CLI executable and RawrXD-RE-Library to the main-tree build.

```cmake
# RawrXD Reverse Engineering Library (CODEX CLI backend)
if(EXISTS "${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/reverse_engineering/CMakeLists.txt")
    add_subdirectory(${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/reverse_engineering EXCLUDE_FROM_ALL)
endif()

# CODEX CLI executable
add_executable(rawrxd-codex
    ${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/reverse_engineering/codex_ide_integration.cpp
)
target_link_libraries(rawrxd-codex PRIVATE RawrXD-RE-Library shlwapi dbghelp)
target_include_directories(rawrxd-codex PRIVATE
    ${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/reverse_engineering
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/~dev/rawrxd/include
)
target_compile_features(rawrxd-codex PRIVATE cxx_std_20)
set_target_properties(rawrxd-codex PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    WIN32_EXECUTABLE TRUE
)
```

**Also:** Add `RawrXD-RE-Library` link to the production Win32 IDE target (already done in ~dev line 7538, needs to be in main tree).

**Verification receipt:**
- `cmake` configure succeeds with `RawrXD-RE-Library` and `rawrxd-codex` targets listed.
- `cmake --build --target rawrxd-codex` produces `bin/rawrxd-codex.exe`.
- `rawrxd-codex.exe list-arch` outputs supported architectures.
- `rawrxd-codex.exe decode x64 4889C8` decodes `mov rax, rcx`.

---

## PATCH-002: RawrXD_Disasm_Kernel.asm — missing source

**File:** Referenced in `F:\rawrxd\~dev\rawrxd\CMakeLists.txt` lines 249, 259.

**Problem:** The file does not exist on disk at `F:\rawrxd\src\asm\RawrXD_Disasm_Kernel.asm`. The `rawrxd` executable target (guarded by `RAWRXD_BUILD_CLI=ON`) cannot link because `ml64.exe` will fail on a missing input.

**Actions:**
1. Search backups, stashes, and worktrees for `RawrXD_Disasm_Kernel.asm`:
   - `F:\rawrxd\backup\`
   - `F:\rawrxd\.archived_orphans\`
   - `F:\rawrxd\.backups\`
   - `F:\rawrxd\recovery\stashes\`
   - `F:\rawrxd\~dev\rawrxd\src\asm\`
2. If found: copy to `F:\rawrxd\src\asm\RawrXD_Disasm_Kernel.asm`.
3. If not found: recreate a minimal MASM64 disassembly kernel that exports the symbols expected by the `rawrxd` target, or remove the reference from CMake and mark the CLI target as `EXCLUDE_FROM_ALL` until source is recovered.
4. Verify assembly: `ml64.exe /c /Zi /Cx /W3 /FoRawrXD_Disasm_Kernel.obj RawrXD_Disasm_Kernel.asm`.

**Verification receipt:**
- `ml64.exe` produces `RawrXD_Disasm_Kernel.obj` with no errors.
- `cmake --build --target rawrxd` (with `RAWRXD_BUILD_CLI=ON`) links successfully.

---

## PATCH-003: IDETestAgent.h — replace logging-only tests with assertions

**File:** `F:\rawrxd\src\win32app\IDETestAgent.h`

**Problem:** `runTest()` marks pass on no-throw. 20+ tests are logging-only and counted as PASS without verification.

**Changes:**
1. Modify `runTest()` to require an explicit assertion result. Change signature to `runTest(name, testFunc)` where `testFunc` returns `bool` or throws on failure. A callback that only logs and returns void must be treated as FAIL.
2. Replace logging-only tests with real assertions:

| Test | Current (defective) | Required assertion |
|------|---------------------|-------------------|
| testPowerShellExecution | Logs only | Run `pwsh -Command "Get-Host"`; verify exit code 0 and non-empty output |
| testModelInference | Logs only | Load a tiny GGUF via Deep2; generate >= 1 token; verify output non-empty |
| testAgenticCommands | Logs only | Dispatch a real agent tool via CommandBus; verify command executed |
| testBreakpoints | Logs only | Set a breakpoint in Win32IDE_Debugger; hit it; verify stopped state |
| testSyntaxHighlighting | Logs only | Insert colored text into RichEdit; verify character format applied |
| testSidebar | Logs only | FindWindowEx SysTreeView32; verify handle non-null and item count > 0 |
| testActivityBar | Logs only | Find activity bar HWND; verify visible |
| testTerminal | Logs only | Create terminal pane; verify ConPTY process running |
| testDebugger | Logs only | Verify debugger backend initialized |
| testWatchVariables | Logs only | Add watch; verify variable value retrieved |

3. Missing toolbar/explorer tree: change from LOG_WARNING to throw `std::runtime_error` (FAIL).

**Verification receipt:**
- Build `test_runner` executable.
- Run with `--headless`. Every test that previously logged-only now either passes with real evidence or fails with a specific error message.
- Zero tests pass solely on no-throw.

---

## PATCH-004: test_runner.cpp — readiness polling + configurable output

**File:** `F:\rawrxd\src\win32app\test_runner.cpp`

**Changes:**
1. Replace `Sleep(500)` (line 57) with a readiness poll loop:
   ```cpp
   // Wait up to 10 seconds for the IDE window to be ready
   bool ready = false;
   for (int i = 0; i < 100 && !ready; ++i) {
       HWND hwnd = ide.getMainWindow();
       if (hwnd && IsWindow(hwnd) && IsWindowVisible(hwnd)) {
           ready = true;
           break;
       }
       Sleep(100);
   }
   if (!ready) throw std::runtime_error("IDE window did not become ready within 10s");
   ```
2. Replace hardcoded `C:\RawrXD_IDE_TestResults.txt` (line 92) with configurable path:
   ```cpp
   std::string outputPath = "C:\\RawrXD_IDE_TestResults.txt";
   for (int i = 1; i < argc; i++) {
       if (std::string(argv[i]) == "--output" && i + 1 < argc) {
           outputPath = argv[++i];
       }
   }
   std::ofstream resultFile(outputPath);
   ```
3. Add `--headless` already exists; keep.

**Verification receipt:**
- `test_runner.exe --headless --output F:\temp\test_results.txt` writes results to the specified path.
- No fixed 500ms blind wait; readiness is confirmed before tests run.

---

## PATCH-005: Win32IDE_PowerShell.cpp — remove ExecutionPolicy Bypass, safe args

**File:** `F:\rawrxd\src\win32app\Win32IDE_PowerShell.cpp` (918 lines)

**Changes:**
1. Line 15: Remove `-ExecutionPolicy Bypass` from `executePowerShellScript`. Use:
   ```cpp
   std::string command = "powershell.exe -NoProfile -File \"" + scriptPath + "\"";
   ```
   Pass script arguments via PowerShell's `-ArgumentList` or write args to a temp file and use `-Command` with proper escaping, never by concatenating raw user input into a shell string.
2. Line 43: `executePowerShellCommand` — avoid embedding the command in a `-Command` string. Use `powershell.exe -NoProfile -Command -` with stdin, or use `Add-Type`/C# to invoke PowerShell runspaces directly via the .NET API (no shell string).
3. Line 109: Parse `Get-Module` JSON output with nlohmann/json instead of string search for `"Name":`.
4. Add ConPTY-based interactive terminal path (Win32 `CreatePseudoConsole` + `CreateProcessW` with `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`) as the primary terminal execution path, replacing fire-and-forget `CreateProcessA`.

**Verification receipt:**
- `executePowerShellScript("test.ps1", {})` runs without `-ExecutionPolicy Bypass`.
- PowerShell arguments containing spaces and special characters are passed correctly (no shell injection).
- `getPowerShellModules()` returns valid module names parsed from JSON.
- Interactive ConPTY terminal runs `pwsh.exe`, accepts input, and returns exit code.

---

## PATCH-006: LSP client — native JSON-RPC over pipes

**File:** New file `F:\rawrxd\src\lsp_client_native.cpp` (or replace `lsp_client.cpp` when Qt is absent)

**Problem:** `lsp_client.cpp` depends on `QProcess`, `QJsonDocument`, `QObject`. No native LSP client exists.

**Changes:**
1. Implement `NativeLSPClient` using Win32 anonymous pipes (`CreatePipe`) and `CreateProcessW` to launch the language server.
2. Implement JSON-RPC message framing (Content-Length header + JSON body).
3. Parse JSON with vendored `nlohmann/json` (already at `include/nlohmann/json.hpp`).
4. Implement `initialize`, `initialized`, `textDocument/didOpen`, `textDocument/completion`, `textDocument/hover`, `textDocument/definition`, `textDocument/publishDiagnostics` handling.
5. Register with Win32IDE command surface and connect editor diagnostics display.
6. Build guard: compile only when Qt6 is NOT found, or as a separate target `RawrXD-LSP-Native`.

**Verification receipt:**
- Launch a real LSP server (e.g., clangd or a test server) over pipes.
- Send `initialize`; receive `initialized` response.
- Open a document; receive diagnostics.
- Request completion at a position; receive completion items.
- All without Qt6 linked.

---

## PATCH-007: Terminal — verify Win32TerminalManager ConPTY

**File:** `F:\rawrxd\src\win32app\Win32TerminalManager.cpp` / `.h`

**Changes:**
1. Verify ConPTY creation: `CreatePseudoConsole`, `ResizePseudoConsole`, `ClosePseudoConsole`.
2. Verify process lifecycle: `CreateProcessW` with `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`, `STARTUPINFOEXW`.
3. Verify signal handling: `Ctrl+C` / `Ctrl+Break` forwarding via `GenerateConsoleCtrlEvent`.
4. Verify exit codes: `GetExitCodeProcess` after terminal process ends.
5. Verify cancellation: `TerminateProcess` + `ClosePseudoConsole` cleanup.
6. Verify output capture: read from pseudo-console reader thread; write input via `WriteFile` to input handle.

**Verification receipt:**
- Launch `pwsh.exe` in a ConPTY terminal pane.
- Send `Get-Host | Select-Object Version`; verify version output appears.
- Send `exit`; verify exit code 0 captured.
- Send `Ctrl+C`; verify running command is interrupted.

---

## PATCH-008: Settings persistence — native JSON config store

**File:** New `F:\rawrxd\src\settings_store.cpp` / `settings_store.h` (or connect existing `settings.cpp`)

**Problem:** Qt `settings_manager.cpp` exists but native settings persistence is unverified.

**Changes:**
1. Implement `SettingsStore` using Win32 file I/O + JSON serialization (nlohmann/json, vendored).
2. Store at `%LOCALAPPDATA%\RawrXD\settings.json` (or configurable path).
3. Methods: `Load()`, `Save()`, `Get<T>(key)`, `Set<T>(key, value)`.
4. Connect Win32IDE settings panel to `SettingsStore`.
5. Test: change a setting, restart RawrXD, verify setting survives.

**Verification receipt:**
- `SettingsStore::Set("gpu_backend", "vulkan")` then `Save()`.
- Restart process; `SettingsStore::Load()` returns `"vulkan"`.
- Settings survive restart.

---

## PATCH-009: Debugger variable inspection

**File:** `F:\rawrxd\src\win32app\Win32IDE_Debugger.cpp` + native panel

**Changes:**
1. Connect `Win32IDE_Debugger.cpp` backend to the native debug panel in `Win32IDE_Sidebar.cpp` (Run & Debug view).
2. Implement breakpoint setting: `DebugBreak` / `INT3` injection or debug API (`DebugActiveProcess`, `WaitForDebugEvent`).
3. Implement variable inspection: read memory via `ReadProcessMemory`, interpret types from PDB (dbghelp) or simple type tags.
4. Implement step-over, step-into, continue.
5. Test: launch a test executable, set breakpoint, hit it, inspect a variable value.

**Verification receipt:**
- Debug session launches target process.
- Breakpoint is hit; execution stops.
- Variable `x` with value `42` is displayed in the watch panel.
- Continue/resume works.

---

## PATCH-010: Extensions — verify activation, remove false-success hosts

**File:** `F:\rawrxd\src\win32app\Win32IDE_ExtensionCert.cpp` + any `extension_host_production.cpp` / `js_extension_host_production.cpp` in `~dev` tree

**Problem:** Batch 6 found extension hosts that return `true` without executing commands.

**Changes:**
1. Locate any `ExecuteCommand` / `ExecuteScript` / `LoadExtension` that returns success without work.
2. Replace with real implementation or make them fail explicitly with `NOT_IMPLEMENTED`.
3. Connect real extension host to Win32IDE command surface.
4. Test: load a real extension, register a command, execute it, observe result.

**Verification receipt:**
- Extension loads and registers command `test.extension`.
- Executing `test.extension` produces observable output.
- Unknown command returns explicit failure, not silent success.

---

## PATCH-011: GGUF streaming — confirm native loader wired

**File:** `F:\rawrxd\src\streaming_gguf_loader.cpp` (695 lines)

**Status:** Native loader exists. Already in `deep2_engine_lib` build (F:\rawrxd\CMakeLists.txt deep2 section).

**Changes:** None needed for source. Add verification test.

**Verification receipt:**
- Load a real GGUF model (e.g., TinyLlama or Phi-3 Q4_K_M).
- Verify header parsed, metadata parsed, tensor index built, zones assigned.
- Verify `Open` returns true, `Close` releases resources.

---

## PATCH-012: GPU backend selector — verify device selection

**File:** `F:\rawrxd\src\hardware_backend_selector.h` / `.cpp`

**Changes:**
1. Verify `hardware_backend_selector.h` enumerates GPU devices (Radeon R9700, RX 7800 XT).
2. Verify selecting a device routes inference to that backend.
3. Verify Vulkan/HIP/CUDA fallback when preferred backend unavailable.

**Verification receipt:**
- Select AMD GPU; verify Deep2 routes matmul to Vulkan/HIP backend.
- Fallback to CPU when no GPU backend available.

---

## PATCH-013: CODEX CLI-to-IDE routing

**File:** `F:\rawrxd\src\win32app\Win32IDE_Commands.cpp` + `Win32IDE_CommandIDs.h`

**Changes:**
1. Register command IDs: `IDM_CODEX_DECODE`, `IDM_CODEX_DISASM`, `IDM_CODEX_ANALYZE`, `IDM_CODEX_LIST_ARCH`.
2. Add menu items: `Tools > CODEX > Decode`, `Disassemble`, `Analyze Binary`, `List Architectures`.
3. Add keyboard shortcut: `Ctrl+Shift+C` (previously reported).
4. Route command execution to `rawrxd-codex.exe` via `CaptureProcessOutput` or direct `rawrxd-codex` library call.
5. Display results in output panel.

**Verification receipt:**
- `Ctrl+Shift+C` opens CODEX command palette.
- Selecting "Disassemble Binary" prompts for a `.exe` file.
- Disassembly output appears in output panel.
- PE analysis output (headers, sections, imports, exports, resources) appears.

---

## PATCH-014: QtLogCompat shim — replace Qt logging calls

**File:** `F:\rawrxd\src\win32app\QtLogCompat.h`, `Win32IDE_VSCodeUI.cpp`, `Win32IDE_Sidebar.cpp`

**Changes:**
1. Replace `qDebug()`, `qInfo()`, `qWarning()`, `qCritical()` calls in native translation units with direct `IDELogger::getInstance().log(...)` calls.
2. Keep `QtLogCompat.h` as a fallback for any remaining Qt-coupled code.
3. Verify build without Qt6 still works.

**Verification receipt:**
- Build with Qt6 not found: no "identifier not found" errors for qInfo/qDebug.
- Log messages appear in `.\RawrXD_IDE.log`.

---

## PATCH-015: Codec/zlib replacement

**File:** `F:\rawrxd\src\qtapp\codec.cpp` (Qt+zlib) vs `F:\rawrxd\src\qtapp\inflate_deflate_cpp.cpp` (MASM)

**Changes:**
1. Confirm `brutal_compression_lib` (MASM deflate + BrutalGzip) is linked into production targets.
2. Verify Qt `codec.cpp` is not required by any native target.
3. Test compression/decompression round-trip without zlib.

**Verification receipt:**
- Build without zlib (`HAVE_ZLIB=0`).
- Compress data with BrutalGzip; decompress; verify byte-identical output.

---

## PATCH-016: Symbol index buildIndex (if present locally)

**File:** `F:\rawrxd\~dev\rawrxd\src\core\symbol_index_impl.cpp` (GitHub-referenced; check local presence)

**Problem:** `SymbolIndex::buildIndex()` is empty (no-op) in checked-in source.

**Changes:**
1. Implement `buildIndex(uri, text)` to parse text, extract symbols, add to index via `addSymbol()`.
2. Connect to `FileWatcher` for automatic re-indexing on file change.
3. Connect to editor for symbol navigation and autocomplete.

**Verification receipt:**
- `buildIndex("file:///test.cpp", "int foo() {}")` populates index.
- `findByName("foo")` returns the symbol.

---

## PATCH-017: Extension hosts — remove false-success

**File:** `F:\rawrxd\~dev\rawrxd\src\core\extension_host_production.cpp` and `js_extension_host_production.cpp` (GitHub-referenced)

**Problem:** `ExecuteCommand` returns `true` without looking up or invoking the command.

**Changes:**
1. Replace `ExecuteCommand` with real command lookup and dispatch, or make it return `false` / throw `NOT_IMPLEMENTED`.
2. Same for `ExecuteScript` and `LoadExtension` in JS host.

**Verification receipt:**
- `ExecuteCommand("nonexistent.command", "")` returns `false`.
- A registered command executes and produces a result.

---

## PATCH-018: Model loader — remove fake GGUF loader

**File:** `F:\rawrxd\~dev\rawrxd\src\core\model_loader_production.cpp` (GitHub-referenced)

**Problem:** `Open()` returns `!path.empty()` without opening a file. `ParseHeader()` and `ParseTensors()` return `true` unconditionally.

**Changes:**
1. Replace with real Deep2 GGUF loader (`streaming_gguf_loader.cpp` or `gguf_loader.cpp`).
2. Or make methods return `false` / throw until real implementation is connected.

**Verification receipt:**
- `Open("nonexistent.gguf")` returns `false`.
- `Open(valid.gguf)` returns `true` and parses header/tensors.

---

## Acceptance criteria per patch

Each patch is complete only when:
1. **Source:** No Qt dependency in the production target.
2. **Wiring:** Reachable from the launched native executable.
3. **Behavior:** Real user interaction performs the intended operation.
4. **Evidence:** A reproducible receipt proves it works.

Patches that fail any criterion remain open in the REMAINING_WORK_LEDGER.
