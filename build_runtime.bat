@echo off
REM ============================================================================
REM Build Script: Sovereign Shared Memory Runtime Server
REM ============================================================================

setlocal enabledelayedexpansion

REM Tool paths
set VSROOT=C:\Program Files\Microsoft Visual Studio\18\Enterprise
set ML64="%VSROOT%\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe"
set CL="%VSROOT%\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe"
set LINK="%VSROOT%\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe"

REM Include paths
set INCLUDE=%VSROOT%\VC\Tools\MSVC\14.51.36231\include;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt
set LIB=%VSROOT%\VC\Tools\MSVC\14.51.36231\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64

REM Directories
set SRC_DIR=d:\RawrXD\src\runtime
set OUT_DIR=d:\RawrXD\bin
set OBJ_DIR=d:\RawrXD\obj\runtime

REM Create directories
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"
if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"

echo ============================================================================
echo Building Sovereign Shared Memory Runtime Server
echo ============================================================================
echo.

REM Compile server implementation
echo [1/4] Compiling SovereignSharedMemoryServer.cpp...
%CL% /c /W4 /EHsc /O2 /nologo /Zi /Fo"%OBJ_DIR%\SovereignSharedMemoryServer.obj" /I"d:\RawrXD\src" "%SRC_DIR%\SovereignSharedMemoryServer.cpp"
if errorlevel 1 goto :error

REM Compile main executable
echo [2/4] Compiling SovereignRuntimeMain.cpp...
%CL% /c /W4 /EHsc /O2 /nologo /Zi /Fo"%OBJ_DIR%\SovereignRuntimeMain.obj" /I"d:\RawrXD\src" "%SRC_DIR%\SovereignRuntimeMain.cpp"
if errorlevel 1 goto :error

REM Compile test client
echo [3/4] Compiling SovereignRuntimeTestClient.cpp...
%CL% /c /W4 /EHsc /O2 /nologo /Zi /Fo"%OBJ_DIR%\SovereignRuntimeTestClient.obj" /I"d:\RawrXD\src" "%SRC_DIR%\SovereignRuntimeTestClient.cpp"
if errorlevel 1 goto :error

REM Link runtime server executable
echo [4/4] Linking SovereignRuntime.exe...
%LINK% /SUBSYSTEM:CONSOLE /OUT:"%OUT_DIR%\SovereignRuntime.exe" kernel32.lib user32.lib libcmt.lib "%OBJ_DIR%\SovereignSharedMemoryServer.obj" "%OBJ_DIR%\SovereignRuntimeMain.obj"
if errorlevel 1 goto :error

REM Link test client executable
echo [5/5] Linking SovereignRuntimeTestClient.exe...
%LINK% /SUBSYSTEM:CONSOLE /OUT:"%OUT_DIR%\SovereignRuntimeTestClient.exe" kernel32.lib user32.lib libcmt.lib "%OBJ_DIR%\SovereignSharedMemoryServer.obj" "%OBJ_DIR%\SovereignRuntimeTestClient.obj"
if errorlevel 1 goto :error

echo.
echo ============================================================================
echo BUILD SUCCESSFUL
echo ============================================================================
echo.
echo Output files:
echo   %OUT_DIR%\SovereignRuntime.exe          (Runtime server)
echo   %OUT_DIR%\SovereignRuntimeTestClient.exe (Test client)
echo.
echo Usage:
echo   1. Start the runtime: SovereignRuntime.exe
echo   2. In another terminal, run: SovereignRuntimeTestClient.exe
echo   3. Or connect IDE via SovereignInferenceBridge_SharedMem.cpp
echo.
goto :end

:error
echo.
echo ============================================================================
echo BUILD FAILED
echo ============================================================================
exit /b 1

:end
endlocal
