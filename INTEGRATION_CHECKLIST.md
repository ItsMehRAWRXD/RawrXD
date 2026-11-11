//=============================================================================
// RawrXD Integration Validation Checklist
// Phase 24/25: Pre-Flight Checklist Before Watch Variables
//=============================================================================

/*

EXECUTIVE SUMMARY
=================

Before proceeding to Watch Variables (which requires expression evaluation),
validate the current stack with this checklist.

CRITICAL PATH VALIDATION
========================

□ 1. Environment Setup
   Command: where cl.exe
   Expected: Path to cl.exe in VS installation
   
   Command: where git.exe
   Expected: Path to git.exe

□ 2. Build All Components
   Command: d:\rawrxd\FinalBuild.bat
   Expected: "[SUCCESS] All components compiled successfully!"
   
   Components Built:
   ✓ DebugBackend.obj (DbgHelp integration)
   ✓ DebugBridge.obj (Event marshaling)
   ✓ DAPAdapter.obj (JSON-RPC protocol)
   ✓ DapService.obj (Production interface)
   ✓ GitHelper.obj (Git integration)
   ✓ StatusBarGitMonitor.obj (Background updates)
   ✓ DAPIntegrationBridge.obj (Win32 glue)
   ✓ BreakpointManagerPanel.obj (UI)
   ✓ BreakpointPropertiesDialog.obj (Modal dialog)

□ 3. Link Executables
   Expected outputs:
   ✓ d:\rawrxd\build\bin\QuickTest.exe
   ✓ d:\rawrxd\build\bin\VerticalTest.exe
   ✓ d:\rawrxd\build\bin\DAPServer.exe

□ 4. Run Component Tests (QuickTest.exe)
   Command: d:\rawrxd\build\bin\QuickTest.exe
   Expected output in d:\rawrxd\build\bin\test_results.txt:
   
   === Test 1: JSON Serialization ===
   PASS: JSON serialization works
   
   === Test 2: JSON Parsing ===
   PASS: JSON parsing works
   
   === Test 3: DebugBridge Events ===
   PASS: DebugBridge events work
   
   === Test 4: DebugBackend API ===
   PASS: DebugBackend API works
   
   Results: 4 passed, 0 failed
   [SUCCESS] All vertical slice tests passed!

□ 5. Run Integration Tests (VerticalTest.exe)
   Command: d:\rawrxd\build\bin\VerticalTest.exe
   Expected: Similar output to QuickTest but with DAPAdapter tests

□ 6. Test DAP Protocol (DAPServer.exe)
   Command: echo {"type":"request","seq":1,"command":"initialize"} | d:\rawrxd\build\bin\DAPServer.exe
   Expected: JSON response with capabilities

□ 7. Test Git Integration
   Command: d:\rawrxd\build\bin\QuickTest.exe
   Check: Git status appears in test output
   Expected: Current branch name displayed

INTEGRATION VALIDATION
======================

□ 8. DAPIntegrationBridge Wiring
   Verify in Win32IDE:
   - WM_USER_DEBUG_EVENT handled
   - WM_USER_DEBUG_PAUSED handled
   - WM_USER_DEBUG_CONTINUED handled
   - WM_USER_GIT_STATUS_UPDATE handled

□ 9. BreakpointManagerPanel Integration
   Verify:
   - Panel creates without errors
   - IBreakpointManagerCallbacks implemented
   - SetCallbacks() called
   - AddBreakpoint() works
   - ToggleBreakpointEnabled() works
   - OnBreakpointNavigate() opens file

□ 10. End-to-End Debug Flow
   Test sequence:
   a. Launch notepad.exe via DAPIntegrationBridge
   b. Set breakpoint on ntdll!NtCreateFile
   c. Continue execution
   d. Trigger breakpoint (open file in notepad)
   e. Verify:
      - Process pauses
      - Call stack populated
      - BreakpointManager shows hit count
      - Can step/continue

□ 11. Git Status Bar
   Verify:
   - Branch name appears in status bar after 30s
   - Updates when switching branches
   - Shows "*" when working tree dirty

□ 12. Thread Safety
   Verify:
   - UI remains responsive during debugging
   - No deadlocks when toggling breakpoints
   - No crashes when rapid stepping

ERROR HANDLING VALIDATION
=========================

□ 13. Graceful Degradation
   Test:
   - Launch without git.exe in PATH
   - Attach to non-existent process
   - Set breakpoint on invalid address
   - Continue when not paused
   
   Expected: Error messages, no crashes

□ 14. Resource Cleanup
   Test:
   - Start/stop debugging 10 times
   - Check Task Manager for leaked processes
   - Verify no handle leaks (Process Explorer)

PERFORMANCE BASELINE
====================

□ 15. Startup Time
   Measure: Time from StartDebugging() to first breakpoint hit
   Target: < 2 seconds for simple executable

□ 16. Memory Usage
   Measure: Working set during debugging
   Target: < 100MB for typical session

□ 17. UI Responsiveness
   Test: Drag window while paused at breakpoint
   Expected: Smooth, no stuttering

SIGN-OFF CRITERIA
=================

Before proceeding to Watch Variables, ALL checks above must pass.

Watch Variables requires:
- Expression evaluation (DAP evaluate request)
- Variable scoping (DAP scopes/variables requests)
- Memory inspection (DAP readMemory request)
- Complex type visualization

These build on the foundation validated above.

TROUBLESHOOTING GUIDE
=====================

Issue: "cl.exe not found"
→ Run from VS Developer Command Prompt
→ Or run: "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvarsall.bat" x64

Issue: "DebugBackend.obj link errors"
→ Check dbghelp.lib is in LIB path
→ Verify Windows SDK is installed

Issue: "Git status not showing"
→ Verify git.exe in PATH
→ Check GitHelper::ExecuteGitCommand returns data

Issue: "DAPServer hangs"
→ Check stdin is redirected: DAPServer.exe < input.txt
→ Verify JSON format is correct

Issue: "Breakpoint panel empty"
→ Verify SetCallbacks() was called
→ Check AddBreakpoint() is being called

Issue: "UI freezes during debug"
→ Verify PostMessage used, not direct calls
→ Check DebugBridge event processing

QUICK TEST SCRIPT
=================

Save as test_integration.bat:

@echo off
cd /d d:\rawrxd

echo Testing RawrXD Debug Integration...
echo.

REM Test 1: Build
call FinalBuild.bat
if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)

REM Test 2: Component Tests
bin\QuickTest.exe
if errorlevel 1 (
    echo COMPONENT TESTS FAILED
    exit /b 1
)

REM Test 3: Check results
if exist bin\test_results.txt (
    findstr "SUCCESS" bin\test_results.txt > nul
    if errorlevel 1 (
        echo TEST RESULTS SHOW FAILURE
        type bin\test_results.txt
        exit /b 1
    )
)

echo.
echo ALL TESTS PASSED!
echo Ready for Watch Variables implementation.
exit /b 0

*/
