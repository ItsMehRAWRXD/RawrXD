@echo off
REM FinalBuild.bat
REM Phase 24E: Production Build Script for RawrXD Debugger
REM ============================================================================

echo ==========================================
echo RawrXD Debugger - Final Production Build
echo ==========================================
echo.

set WORKSPACE=d:\rawrxd
set SRC_DIR=%WORKSPACE%\src\debugger
set EXT_DIR=%WORKSPACE%\src\debug
set BIN_DIR=%WORKSPACE%\bin
set LOG_FILE=%WORKSPACE%\build.log

REM Clean previous build
if exist %LOG_FILE% del %LOG_FILE%
if not exist %BIN_DIR% mkdir %BIN_DIR%

echo [1/6] Checking Visual Studio environment...
where cl.exe > nul 2>&1
if errorlevel 1 (
    echo ERROR: Visual Studio environment not found!
    echo Please run this script from VS Developer Command Prompt
    exit /b 1
)
echo   OK
echo.

echo [2/6] Compiling DAPTransport.cpp...
cl /c /EHsc /O2 /MD /W4 /I%SRC_DIR% /Fo%BIN_DIR%\DAPTransport.obj %SRC_DIR%\DAPTransport.cpp 2>>%LOG_FILE%
if errorlevel 1 (
    echo FAILED! Check build.log
    exit /b 1
)
echo   OK
echo.

echo [3/6] Compiling DAPAdapter.cpp...
cl /c /EHsc /O2 /MD /W4 /I%SRC_DIR% /Fo%BIN_DIR%\DAPAdapter.obj %SRC_DIR%\DAPAdapter.cpp 2>>%LOG_FILE%
if errorlevel 1 (
    echo FAILED! Check build.log
    exit /b 1
)
echo   OK
echo.

echo [4/6] Compiling BeaconDAPServer.cpp...
cl /c /EHsc /O2 /MD /W4 /I%SRC_DIR% /Fo%BIN_DIR%\BeaconDAPServer.obj %SRC_DIR%\BeaconDAPServer.cpp 2>>%LOG_FILE%
if errorlevel 1 (
    echo FAILED! Check build.log
    exit /b 1
)
echo   OK
echo.

echo [5/6] Compiling DapService.cpp (IDE integration)...
cl /c /EHsc /O2 /MD /W4 /I%EXT_DIR% /I%SRC_DIR% /Fo%BIN_DIR%\DapService.obj %EXT_DIR%\DapService.cpp 2>>%LOG_FILE%
if errorlevel 1 (
    echo FAILED! Check build.log
    exit /b 1
)
echo   OK
echo.

echo [6/6] Linking BeaconDebugger.exe...
link.exe /OUT:%BIN_DIR%\BeaconDebugger.exe ^
    %BIN_DIR%\BeaconDAPServer.obj ^
    %BIN_DIR%\DAPAdapter.obj ^
    %BIN_DIR%\DAPTransport.obj ^
    %BIN_DIR%\DapService.obj ^
    %SRC_DIR%\RawrXD_BeaconDebugger_ABI_Fixed.obj ^
    kernel32.lib user32.lib ^
    /SUBSYSTEM:CONSOLE /LARGEADDRESSAWARE:NO 2>>%LOG_FILE%
if errorlevel 1 (
    echo FAILED! Check build.log
    exit /b 1
)
echo   OK
echo.

echo ==========================================
echo BUILD SUCCESSFUL!
echo ==========================================
echo.
echo Output: %BIN_DIR%\BeaconDebugger.exe
echo.
echo Next steps:
echo   1. Build Victim.exe: ml64 Victim.asm /link /out:Victim.exe
echo   2. Open VS Code in %WORKSPACE%
echo   3. Press F5, select "RawrXD: Launch Program"
echo   4. Set breakpoint in Victim.asm line 25
echo   5. Verify yellow arrow appears when hit
echo.
