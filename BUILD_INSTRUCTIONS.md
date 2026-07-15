//=============================================================================
// RawrXD Build Instructions
// How to compile the debug stack from VS Developer Command Prompt
//=============================================================================

/*

QUICK START (VS Developer Command Prompt)
========================================

1. Open "Developer Command Prompt for VS 2022" (x64)
   - Start Menu → Visual Studio 2022 → Developer Command Prompt
   
2. Navigate to project:
   cd d:\rawrxd
   
3. Run manual build:
   ManualBuild.bat
   
4. Expected output:
   [1/8] DebugBackend.cpp
   [2/8] DebugBridge.cpp
   [3/8] DAPAdapter.cpp
   [4/8] DapService.cpp
   [5/8] GitHelper.cpp
   [6/8] StatusBarGitMonitor.cpp
   [7/8] DAPIntegrationBridge.cpp
   [8/8] BreakpointManagerPanel.cpp
   
   Linking executables...
   - QuickTest.exe
   - VerticalTest.exe
   - DAPServer.exe
   
   BUILD SUCCESSFUL

MANUAL COMPILATION (if batch fails)
====================================

If the batch script has issues, compile manually:

Step 1: Set paths
-----------------
set SRC=d:\rawrxd\src
set OUT=d:\rawrxd\build\bin
if not exist "%OUT%" mkdir "%OUT%"

Step 2: Compile components
----------------------------
cl.exe /nologo /EHsc /O2 /W4 /DUNICODE /D_UNICODE /I"%SRC%\debug" /c "%SRC%\debug\DebugBackend.cpp" /Fo"%OUT%\DebugBackend.obj"

cl.exe /nologo /EHsc /O2 /W4 /DUNICODE /D_UNICODE /I"%SRC%\debug" /c "%SRC%\debug\DebugBridge.cpp" /Fo"%OUT%\DebugBridge.obj"

cl.exe /nologo /EHsc /O2 /W4 /DUNICODE /D_UNICODE /I"%SRC%\debug" /c "%SRC%\debug\DAPAdapter.cpp" /Fo"%OUT%\DAPAdapter.obj"

cl.exe /nologo /EHsc /O2 /W4 /DUNICODE /D_UNICODE /I"%SRC%\debug" /c "%SRC%\debug\DapService.cpp" /Fo"%OUT%\DapService.obj"

cl.exe /nologo /EHsc /O2 /W4 /DUNICODE /D_UNICODE /I"%SRC%\utils" /c "%SRC%\utils\GitHelper.cpp" /Fo"%OUT%\GitHelper.obj"

cl.exe /nologo /EHsc /O2 /W4 /DUNICODE /D_UNICODE /I"%SRC%\win32app" /I"%SRC%\debug" /c "%SRC%\win32app\StatusBarGitMonitor.cpp" /Fo"%OUT%\StatusBarGitMonitor.obj"

cl.exe /nologo /EHsc /O2 /W4 /DUNICODE /D_UNICODE /I"%SRC%\win32app" /I"%SRC%\debug" /c "%SRC%\win32app\DAPIntegrationBridge.cpp" /Fo"%OUT%\DAPIntegrationBridge.obj"

cl.exe /nologo /EHsc /O2 /W4 /DUNICODE /D_UNICODE /I"%SRC%\win32app" /I"%SRC%\debug" /c "%SRC%\win32app\BreakpointManagerPanel.cpp" /Fo"%OUT%\BreakpointManagerPanel.obj"

Step 3: Link executables
------------------------
cl.exe /nologo /EHsc /O2 /W4 "%SRC%\debug\QuickTest.cpp" "%OUT%\DebugBackend.obj" "%OUT%\DebugBridge.obj" "%OUT%\GitHelper.obj" /Fe"%OUT%\QuickTest.exe" /link dbghelp.lib kernel32.lib user32.lib /SUBSYSTEM:CONSOLE

cl.exe /nologo /EHsc /O2 /W4 "%SRC%\debug\VerticalTest.cpp" "%OUT%\DebugBackend.obj" "%OUT%\DebugBridge.obj" "%OUT%\DAPAdapter.obj" "%OUT%\DapService.obj" /Fe"%OUT%\VerticalTest.exe" /link dbghelp.lib kernel32.lib user32.lib /SUBSYSTEM:CONSOLE

cl.exe /nologo /EHsc /O2 /W4 "%SRC%\debug\DAPServer.cpp" "%OUT%\DebugBackend.obj" "%OUT%\DebugBridge.obj" "%OUT%\DAPAdapter.obj" "%OUT%\DapService.obj" /Fe"%OUT%\DAPServer.exe" /link dbghelp.lib kernel32.lib user32.lib /SUBSYSTEM:CONSOLE

TROUBLESHOOTING
===============

Error: "cl.exe is not recognized"
→ You are not in VS Developer Command Prompt
→ Solution: Open "Developer Command Prompt for VS 2022" from Start Menu

Error: "Cannot open include file: 'windows.h'"
→ Windows SDK not installed or not in INCLUDE path
→ Solution: Install Windows SDK via Visual Studio Installer

Error: "Cannot find dbghelp.lib"
→ Windows SDK libraries not in LIB path
→ Solution: Install Windows SDK or add path manually

Error: "LNK2019: unresolved external symbol"
→ Object files not being linked
→ Solution: Check all .obj files are listed in link command

Error: "Access denied"
→ Output directory permissions
→ Solution: Run as Administrator or change output path

VALIDATION
==========

After successful build:

1. Check executables exist:
   dir d:\rawrxd\build\bin\*.exe
   
   Expected:
   - QuickTest.exe
   - VerticalTest.exe
   - DAPServer.exe

2. Run component tests:
   d:\rawrxd\build\bin\QuickTest.exe
   
   Expected: "[SUCCESS] All vertical slice tests passed!"

3. Run integration tests:
   d:\rawrxd\build\bin\VerticalTest.exe
   
   Expected: "Results: X passed, 0 failed"

4. Test DAP protocol:
   echo {"type":"request","seq":1,"command":"initialize"} | d:\rawrxd\build\bin\DAPServer.exe
   
   Expected: JSON response with capabilities

WHAT'S BEEN BUILT
=================

Core Components (8 source files):
1. DebugBackend.cpp      - Windows Debug API + DbgHelp
2. DebugBridge.cpp       - Thread-safe event marshaling
3. DAPAdapter.cpp        - JSON-RPC protocol handlers
4. DapService.cpp        - Async production interface
5. GitHelper.cpp         - Git command execution
6. StatusBarGitMonitor.cpp - Background git updates
7. DAPIntegrationBridge.cpp - Win32IDE glue layer
8. BreakpointManagerPanel.cpp - Breakpoint management UI

Executables (3 binaries):
1. QuickTest.exe         - Component validation
2. VerticalTest.exe      - Full stack integration
3. DAPServer.exe         - Standalone DAP adapter

Total: ~10,000 lines of production code

NEXT STEPS AFTER BUILD
======================

Once build succeeds:
1. Run all tests (QuickTest + VerticalTest)
2. Verify DAPServer responds to initialize
3. Integrate into Win32IDE (see INTEGRATION_GUIDE.md)
4. Proceed to Watch Variables implementation

*/
