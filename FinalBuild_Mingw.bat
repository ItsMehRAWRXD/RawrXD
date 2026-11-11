@echo off
REM FinalBuild_Mingw.bat
REM Phase 24E: Production Build Script for RawrXD Debugger (MinGW Edition)
REM ============================================================================

echo ==========================================
echo RawrXD Debugger - Final Production Build (MinGW)
echo ==========================================
echo.

set WORKSPACE=d:\rawrxd
set ROOT_SRC=%WORKSPACE%\src
set SRC_DIR=%WORKSPACE%\src\debugger
set EXT_DIR=%WORKSPACE%\src\debug
set UI_DIR=%WORKSPACE%\src\ui
set BIN_DIR=%WORKSPACE%\bin
set LOG_FILE=%WORKSPACE%\build_mingw.log

REM Clean previous build
if exist %LOG_FILE% del %LOG_FILE%
if not exist %BIN_DIR% mkdir %BIN_DIR%

echo [1/6] Checking MinGW environment...
where g++.exe > nul 2>&1
if errorlevel 1 (
    echo ERROR: MinGW g++.exe not found in PATH!
    exit /b 1
)
echo   OK
echo.

echo [2/6] Compiling DAPTransport.cpp...
g++.exe -c -std=c++20 -O2 -Wall -I%ROOT_SRC% -I%SRC_DIR% -I%EXT_DIR% -I%UI_DIR% -o %BIN_DIR%\DAPTransport.obj %SRC_DIR%\DAPTransport.cpp 2>>%LOG_FILE%
if errorlevel 1 (
    echo FAILED! Check build_mingw.log
    exit /b 1
)
echo   OK
echo.

echo [3/6] Compiling DAPAdapter.cpp...
g++.exe -c -std=c++20 -O2 -Wall -I%ROOT_SRC% -I%SRC_DIR% -I%EXT_DIR% -I%UI_DIR% -o %BIN_DIR%\DAPAdapter.obj %SRC_DIR%\DAPAdapter.cpp 2>>%LOG_FILE%
if errorlevel 1 (
    echo FAILED! Check build_mingw.log
    exit /b 1
)
echo   OK
echo.

echo [4/6] Compiling BeaconDAPServer.cpp...
g++.exe -c -std=c++20 -O2 -Wall -I%ROOT_SRC% -I%SRC_DIR% -I%EXT_DIR% -I%UI_DIR% -o %BIN_DIR%\BeaconDAPServer.obj %SRC_DIR%\BeaconDAPServer.cpp 2>>%LOG_FILE%
if errorlevel 1 (
    echo FAILED! Check build_mingw.log
    exit /b 1
)
echo   OK
echo.

echo [5/7] Compiling Debugger_Backend.cpp...
g++.exe -c -std=c++20 -O2 -Wall -I%ROOT_SRC% -I%SRC_DIR% -I%EXT_DIR% -I%UI_DIR% -o %BIN_DIR%\Debugger_Backend.obj %SRC_DIR%\Debugger_Backend.cpp 2>>%LOG_FILE%
if errorlevel 1 (
    echo FAILED! Check build_mingw.log
    exit /b 1
)
echo   OK
echo.

echo [6/7] Compiling DapService.cpp (IDE integration)...
g++.exe -c -std=c++20 -O2 -Wall -I%ROOT_SRC% -I%SRC_DIR% -I%EXT_DIR% -I%UI_DIR% -o %BIN_DIR%\DapService.obj %EXT_DIR%\DapService.cpp 2>>%LOG_FILE%
if errorlevel 1 (
    echo FAILED! Check build_mingw.log
    exit /b 1
)
echo   OK
echo.

echo [7/7] Linking BeaconDebugger.exe...
g++.exe -o %BIN_DIR%\BeaconDebugger.exe ^
    %BIN_DIR%\BeaconDAPServer.obj ^
    %BIN_DIR%\DAPAdapter.obj ^
    %BIN_DIR%\DAPTransport.obj ^
    %BIN_DIR%\Debugger_Backend.obj ^
    %BIN_DIR%\DapService.obj ^
    -static-libgcc -static-libstdc++ ^
    -lws2_32 -lkernel32 -luser32 -ldbghelp 2>>%LOG_FILE%
if errorlevel 1 (
    echo FAILED! Check build_mingw.log
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
