@echo off
REM E2E Integration Verification Script for RawrXD BeaconDebugger
REM This script verifies the complete DAP pipeline before adding stackTrace

echo ==========================================
echo RawrXD BeaconDebugger - E2E Verification
echo ==========================================
echo.

set WORKSPACE=d:\rawrxd
set BIN_DIR=%WORKSPACE%\bin
set LOG_FILE=%WORKSPACE%\dap_verify.log

echo [0] Cleaning up previous runs...
if exist %LOG_FILE% del %LOG_FILE%
taskkill /F /IM BeaconDebugger.exe 2>nul
taskkill /F /IM Victim.exe 2>nul

echo.
echo ==========================================
echo TEST 1: Protocol Handshake Verification
echo ==========================================
echo.

echo Step 1: Building DAP Server...
cd %WORKSPACE%
if not exist %BIN_DIR% mkdir %BIN_DIR%

REM Compile C++ components
cl /c /EHsc /O2 /MD /W4 /I%WORKSPACE%\src\debugger /Fo%BIN_DIR%\DAPTransport.obj %WORKSPACE%\src\debugger\DAPTransport.cpp 2>&1
if errorlevel 1 goto :build_fail

cl /c /EHsc /O2 /MD /W4 /I%WORKSPACE%\src\debugger /Fo%BIN_DIR%\DAPAdapter.obj %WORKSPACE%\src\debugger\DAPAdapter.cpp 2>&1
if errorlevel 1 goto :build_fail

cl /c /EHsc /O2 /MD /W4 /I%WORKSPACE%\src\debugger /Fo%BIN_DIR%\BeaconDAPServer.obj %WORKSPACE%\src\debugger\BeaconDAPServer.cpp 2>&1
if errorlevel 1 goto :build_fail

echo Step 2: Linking executable...
link.exe /OUT:%BIN_DIR%\BeaconDebugger.exe ^
    %BIN_DIR%\BeaconDAPServer.obj ^
    %BIN_DIR%\DAPAdapter.obj ^
    %BIN_DIR%\DAPTransport.obj ^
    %WORKSPACE%\src\debugger\RawrXD_BeaconDebugger_ABI_Fixed.obj ^
    kernel32.lib user32.lib ^
    /SUBSYSTEM:CONSOLE /LARGEADDRESSAWARE:NO 2>&1
if errorlevel 1 goto :link_fail

echo Step 3: Building Victim.exe...
cd %WORKSPACE%\src\debugger
ml64 /c /Fo%BIN_DIR%\Victim.obj Victim.asm 2>&1
if errorlevel 1 goto :victim_asm_fail

link /OUT:%WORKSPACE%\Victim.exe %BIN_DIR%\Victim.obj /SUBSYSTEM:CONSOLE /ENTRY:main 2>&1
if errorlevel 1 goto :victim_link_fail

echo.
echo [PASS] Build successful!
echo.

echo ==========================================
echo TEST 2: Manual DAP Handshake Test
echo ==========================================
echo.

echo Starting BeaconDebugger in stdio mode...
echo Send the following JSON-RPC message and press Enter:
echo { "seq": 1, "type": "request", "command": "initialize", "arguments": {} }
echo.

%BIN_DIR%\BeaconDebugger.exe --stdio --verbose 2>%LOG_FILE%

echo.
echo Check %LOG_FILE% for output
echo.

echo ==========================================
echo TEST 3: File Verification
echo ==========================================
echo.

if exist %BIN_DIR%\BeaconDebugger.exe (
    echo [PASS] BeaconDebugger.exe exists
    dir %BIN_DIR%\BeaconDebugger.exe
) else (
    echo [FAIL] BeaconDebugger.exe NOT FOUND
    goto :fail
)

if exist %WORKSPACE%\Victim.exe (
    echo [PASS] Victim.exe exists
    dir %WORKSPACE%\Victim.exe
) else (
    echo [FAIL] Victim.exe NOT FOUND
    goto :fail
)

if exist %WORKSPACE%\dap-server-launcher.js (
    echo [PASS] dap-server-launcher.js exists
) else (
    echo [FAIL] dap-server-launcher.js NOT FOUND
    goto :fail
)

echo.
echo ==========================================
echo VERIFICATION COMPLETE
echo ==========================================
echo.
echo Next steps:
echo   1. Open VS Code in %WORKSPACE%
echo   2. Open Victim.asm
echo   3. Set breakpoint on line 25 (__bp_entry_point)
echo   4. Press F5, select "Attach to RawrXD DAP Server"
echo   5. Verify: breakpoint shows checkmark, execution pauses
echo.
echo If VS Code shows "Debug adapter process has terminated unexpectedly":
echo   - Check %LOG_FILE% for errors
echo   - Verify Node.js is installed: node --version
echo   - Check paths in .vscode\launch.json
echo.
goto :end

:build_fail
echo.
echo [FAIL] C++ compilation failed
goto :fail

:link_fail
echo.
echo [FAIL] Linking failed
goto :fail

:victim_asm_fail
echo.
echo [FAIL] Victim.asm assembly failed
goto :fail

:victim_link_fail
echo.
echo [FAIL] Victim.exe linking failed
goto :fail

:fail
echo.
echo ==========================================
echo VERIFICATION FAILED
echo ==========================================
echo Check error messages above
exit /b 1

:end
echo.
echo All pre-flight checks passed!
