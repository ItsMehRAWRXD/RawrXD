@echo off
REM Build script for BeaconDebugger DAP Server
REM Run this in VS Developer Command Prompt

echo ==========================================
echo RawrXD BeaconDebugger DAP Server Build
echo ==========================================

set SRC_DIR=d:\rawrxd\src\debugger
set OUT_DIR=d:\rawrxd\bin

if not exist %OUT_DIR% mkdir %OUT_DIR%

echo.
echo [1/4] Compiling DAPTransport.cpp...
cl /c /EHsc /O2 /MD /W4 /I%SRC_DIR% /Fo%OUT_DIR%\DAPTransport.obj %SRC_DIR%\DAPTransport.cpp
if errorlevel 1 goto :error

echo.
echo [2/4] Compiling DAPAdapter.cpp...
cl /c /EHsc /O2 /MD /W4 /I%SRC_DIR% /Fo%OUT_DIR%\DAPAdapter.obj %SRC_DIR%\DAPAdapter.cpp
if errorlevel 1 goto :error

echo.
echo [3/4] Compiling BeaconDAPServer.cpp...
cl /c /EHsc /O2 /MD /W4 /I%SRC_DIR% /Fo%OUT_DIR%\BeaconDAPServer.obj %SRC_DIR%\BeaconDAPServer.cpp
if errorlevel 1 goto :error

echo.
echo [4/4] Linking BeaconDebugger.exe...
link.exe /OUT:%OUT_DIR%\BeaconDebugger.exe ^
    %OUT_DIR%\BeaconDAPServer.obj ^
    %OUT_DIR%\DAPAdapter.obj ^
    %OUT_DIR%\DAPTransport.obj ^
    %SRC_DIR%\RawrXD_BeaconDebugger_ABI_Fixed.obj ^
    kernel32.lib user32.lib ^
    /SUBSYSTEM:CONSOLE /LARGEADDRESSAWARE:NO
if errorlevel 1 goto :error

echo.
echo ==========================================
echo Build SUCCESSFUL!
echo Output: %OUT_DIR%\BeaconDebugger.exe
echo ==========================================
goto :end

:error
echo.
echo ==========================================
echo Build FAILED!
echo ==========================================
exit /b 1

:end
echo.
echo Next steps:
echo   1. Build Victim.exe: ml64 Victim.asm /link /out:Victim.exe
echo   2. Open VS Code in d:\rawrxd
echo   3. Press F5 to start debugging
