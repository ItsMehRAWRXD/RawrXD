//=============================================================================
// RawrXD Debugger Integration Guide
// Phase 24-25: From Verified Backend to VS Code Extension
//=============================================================================

/*

ARCHITECTURE OVERVIEW
=====================

┌─────────────────────────────────────────────────────────────────────────────┐
│                           VS CODE EXTENSION                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Debug     │  │  Call Stack │  │  Variables  │  │ Breakpoints │         │
│  │   Panel     │  │   Panel     │  │   Panel     │  │   Panel     │         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
│         │                │                │                │               │
│         └────────────────┴────────────────┴────────────────┘               │
│                                    │                                        │
│                         ┌──────────▼──────────┐                           │
│                         │  DebugConfiguration │                           │
│                         │     Provider        │                           │
│                         └──────────┬──────────┘                           │
│                                    │                                        │
└────────────────────────────────────┼────────────────────────────────────────┘
                                     │
                              DAP Protocol
                              (JSON-RPC over stdio)
                                     │
┌────────────────────────────────────┼────────────────────────────────────────┐
│                         RawrXD IDE │ DAPServer.exe                           │
│  ┌─────────────────────────────────▼────────────────────────────────┐      │
│  │                      DAPTransport (DAPTransport.hpp)              │      │
│  │  - Content-Length framing                                         │      │
│  │  - JSON serialization (JSONWriter/JSONParser)                     │      │
│  └─────────────────────────────────┬────────────────────────────────┘      │
│                                    │                                        │
│                         ┌──────────▼──────────┐                           │
│                         │   DAPAdapter        │                           │
│                         │   (DAPAdapter.hpp)  │                           │
│  ┌──────────────────────┴─────────────────────┴──────────────────────┐     │
│  │                         DapService                                 │     │
│  │                    (DapService.hpp/cpp)                            │     │
│  │  - Session lifecycle management                                   │     │
│  │  - Request/response correlation                                   │     │
│  │  - Event dispatch to UI callbacks                                   │     │
│  └──────────────────────────────┬─────────────────────────────────────┘     │
│                                 │                                           │
│  ┌──────────────────────────────▼─────────────────────────────────────┐      │
│  │                      DebugBackend (DebugBackend.h)                │      │
│  │  - DebugSession: Launch, Attach, Detach                          │      │
│  │  - Execution: Continue, Step, Pause                              │      │
│  │  - Breakpoints: Set, Clear, Enable/Disable                         │      │
│  │  - Inspection: StackWalk, Registers, Memory                      │      │
│  └──────────────────────────────┬─────────────────────────────────────┘      │
│                                 │                                           │
│  ┌──────────────────────────────▼─────────────────────────────────────┐      │
│  │                      DebugBridge (DebugBridge.hpp)                │      │
│  │  - Thread-safe event queue                                       │      │
│  │  - UI thread marshalling via PostMessage                         │      │
│  └──────────────────────────────┬─────────────────────────────────────┘      │
│                                 │                                           │
│  ┌──────────────────────────────▼─────────────────────────────────────┐      │
│  │                      Windows Debug API                            │      │
│  │  - CreateProcess(DEBUG_PROCESS)                                  │      │
│  │  - WaitForDebugEvent / ContinueDebugEvent                        │      │
│  │  - ReadProcessMemory / WriteProcessMemory                        │      │
│  │  - StackWalk64 / SymFromAddr (DbgHelp)                           │      │
│  └───────────────────────────────────────────────────────────────────┘      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

VERIFICATION STATUS
===================

✅ Phase 23: DebugBackend
   - DbgHelp integration (SymInitialize, StackWalk64, SymFromAddr)
   - Debug API integration (CreateProcess with DEBUG_PROCESS)
   - Breakpoint management (INT3 injection)
   - Single-stepping (Trap Flag)
   - Memory read/write
   - Register context capture
   Status: COMPILED, TESTED (DebugTest.exe)

✅ Phase 24: Debug UI (Win32)
   - BreakpointGutter (owner-drawn)
   - CallStackPanel (TreeView)
   - RegisterPanel (ListView)
   - MemoryPanel (hex dump)
   - DebugToolbar
   - DebugEventLog
   Status: COMPLETE

✅ Phase 24.5: DapService
   - Production-ready interface
   - Async-by-default design
   - State machine driven
   - Thread-safe
   Status: IMPLEMENTED, TESTED (DapService_test.cpp)

✅ Phase 25: DAP Adapter
   - DAPTypes.hpp: Protocol structures
   - DAPTransport.hpp: JSON + Content-Length
   - DAPAdapter.hpp/cpp: Request handlers
   - DAPServer.cpp: Standalone entry point
   Status: IMPLEMENTED

🔄 Phase 25.5: Vertical Slice Validation (IN PROGRESS)
   - QuickTest.cpp: Component tests
   - VerticalTest.cpp: Full stack tests
   - run_tests.ps1: Automated runner
   Status: READY TO RUN

⏳ Phase 26: VS Code Extension
   - package.json: Extension manifest
   - extension.ts: Glue code
   - DebugConfigurationProvider
   Status: NOT STARTED

NEXT STEPS
==========

1. RUN VERTICAL SLICE TESTS
   -------------------------
   Open PowerShell and run:
   
   cd d:\rawrxd
   .\run_tests.ps1
   
   Expected output:
   - "Initializing Visual Studio Environment..."
   - "Building QuickTest.exe..."
   - "Running Vertical Slice Tests..."
   - "Results: 4 passed, 0 failed"
   - "[SUCCESS] All vertical slice tests passed!"
   
   If tests fail, review d:\rawrxd\build\bin\test_results.txt

2. BUILD DAPSERVER.EXE
   --------------------
   Once tests pass, build the standalone DAP server:
   
   cl.exe /nologo /EHsc /O2 /W4 /DUNICODE /D_UNICODE ^
       /I"d:\rawrxd\src\debug" ^
       "d:\rawrxd\src\debug\DAPServer.cpp" ^
       "d:\rawrxd\src\debug\DAPAdapter.cpp" ^
       "d:\rawrxd\src\debug\DebugBackend.cpp" ^
       "d:\rawrxd\src\debug\DebugBridge.cpp" ^
       /Fe"d:\rawrxd\build\bin\DAPServer.exe" ^
       /link dbghelp.lib kernel32.lib user32.lib

3. TEST DAP PROTOCOL
   ------------------
   Run the Python test harness:
   
   python d:\rawrxd\src\debug\dap_test_harness.py ^
       --server d:\rawrxd\build\bin\DAPServer.exe ^
       --verbose
   
   Or manually test:
   
   d:\rawrxd\build\bin\DAPServer.exe < d:\rawrxd\src\debug\test_messages.txt

4. CREATE VS CODE EXTENSION
   -------------------------
   Create d:\rawrxd\src\debug\vscode-extension\src\extension.ts:
   
   ```typescript
   import * as vscode from 'vscode';
   
   export function activate(context: vscode.ExtensionContext) {
       // Register debug adapter descriptor factory
       context.subscriptions.push(
           vscode.debug.registerDebugAdapterDescriptorFactory('rawrxd', {
               createDebugAdapterDescriptor(session: vscode.DebugSession) {
                   return new vscode.DebugAdapterExecutable(
                       'd:\\rawrxd\\build\\bin\\DAPServer.exe',
                       []
                   );
               }
           })
       );
       
       // Register configuration provider
       context.subscriptions.push(
           vscode.debug.registerDebugConfigurationProvider('rawrxd', {
               provideDebugConfigurations(folder: vscode.WorkspaceFolder | undefined) {
                   return [{
                       name: 'RawrXD Debug (Launch)',
                       type: 'rawrxd',
                       request: 'launch',
                       program: '${workspaceFolder}/build/Debug/app.exe'
                   }];
               }
           })
       );
   }
   
   export function deactivate() {}
   ```

5. INTEGRATE WITH RAWRXD IDE
   --------------------------
   Modify Win32IDE to use DapService:
   
   ```cpp
   // In Win32IDE initialization
   auto& dapService = RawrXD::DAPService::instance();
   
   DAPService::Callbacks callbacks;
   callbacks.onStopped = [](const std::string& reason, uint32_t threadId) {
       // Update UI: show current line, populate call stack
       UpdateDebugUI(threadId);
   };
   callbacks.onStackTraceReceived = [](const std::vector<StackFrame>& frames) {
       // Populate CallStackPanel
       g_callStackPanel->SetFrames(frames);
   };
   // ... etc
   
   dapService.setCallbacks(callbacks);
   ```

FILES REFERENCE
===============

Core Implementation:
- d:\rawrxd\src\debug\DebugBackend.h          - DebugBackend API
- d:\rawrxd\src\debug\DebugBackend.cpp         - DbgHelp implementation
- d:\rawrxd\src\debug\DebugBridge.hpp         - Event bridge
- d:\rawrxd\src\debug\DebugBridge.cpp         - Implementation
- d:\rawrxd\src\debug\DebugUI.hpp             - Win32 UI panels
- d:\rawrxd\src\debug\DebugUI.cpp             - UI implementation

DAP Layer:
- d:\rawrxd\src\debug\DAPTypes.hpp            - DAP protocol structures
- d:\rawrxd\src\debug\DAPTransport.hpp        - JSON + Content-Length
- d:\rawrxd\src\debug\DAPAdapter.hpp         - Adapter interface
- d:\rawrxd\src\debug\DAPAdapter.cpp         - Request handlers
- d:\rawrxd\src\debug\DAPServer.cpp          - Standalone entry point

Service Layer:
- d:\rawrxd\src\debug\DapService.hpp         - Production interface
- d:\rawrxd\src\debug\DapService.cpp          - Implementation
- d:\rawrxd\src\debug\DapService_test.cpp     - Unit tests

Testing:
- d:\rawrxd\src\debug\QuickTest.cpp           - Component tests
- d:\rawrxd\src\debug\VerticalTest.cpp        - Full stack tests
- d:\rawrxd\src\debug\run_tests.ps1           - Automated runner
- d:\rawrxd\src\debug\dap_test_harness.py     - Protocol tests
- d:\rawrxd\src\debug\test_messages.txt       - Manual test messages

VS Code Extension:
- d:\rawrxd\src\debug\vscode-extension\package.json    - Extension manifest
- d:\rawrxd\src\debug\vscode-extension\src\extension.ts - Glue code (TODO)

BUILD COMMANDS
==============

# Quick test (no CMake required)
d:\rawrxd\src\debug\build_quick.bat

# Full build with CMake
cd d:\rawrxd\build
cmake --build . --target VerticalTest --config Release

# Run tests
d:\rawrxd\build\bin\VerticalTest.exe
type d:\rawrxd\build\bin\test_results.txt

# Or use PowerShell
cd d:\rawrxd
.\run_tests.ps1

*/
