@echo off
:: Build Memory Bridge
::
:: Date: July 10, 2026

echo ============================================================================
echo Memory Bridge Build
echo ============================================================================
echo.

setlocal enabledelayedexpansion

:: Configuration
set SRC_DIR=d:\src\asm
set OUT_DIR=%SRC_DIR%\bin
set VS_ROOT=C:\Program Files\Microsoft Visual Studio\18\Enterprise
set MSVC_VER=14.51.36231
set "VS_TOOLS=%VS_ROOT%\VC\Tools\MSVC\%MSVC_VER%\bin\Hostx64\x64"

:: Create output directory
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

:: Setup environment
set "INCLUDE=%VS_ROOT%\VC\Tools\MSVC\%MSVC_VER%\include;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared"
set "LIB=%VS_ROOT%\VC\Tools\MSVC\%MSVC_VER%\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
set "PATH=%VS_TOOLS%;%PATH%"

:: Tool paths
set "CL=%VS_TOOLS%\cl.exe"
set "LIB_TOOL=%VS_TOOLS%\lib.exe"

:: Compiler flags
set CFLAGS=/c /O2 /W3 /nologo /EHsc /MD /I"%SRC_DIR%"

echo [1/3] Compiling SovereignMemoryBridge.cpp...
"%CL%" %CFLAGS% /Fo"%OUT_DIR%\SovereignMemoryBridge.obj" "%SRC_DIR%\SovereignMemoryBridge.cpp"
if errorlevel 1 (
    echo ERROR: Compilation failed!
    exit /b 1
)
echo     OK: SovereignMemoryBridge.obj

echo.
echo [2/3] Creating library...
"%LIB_TOOL%" /nologo /out:"%OUT_DIR%\SovereignMemoryBridge.lib" "%OUT_DIR%\SovereignMemoryBridge.obj"
if errorlevel 1 (
    echo ERROR: Library creation failed!
    exit /b 1
)
echo     OK: SovereignMemoryBridge.lib

echo.
echo [3/3] Compiling test...
"%CL%" %CFLAGS% /Fo"%OUT_DIR%\test_memory_bridge.obj" "%SRC_DIR%\test_memory_bridge.cpp"
if errorlevel 1 (
    echo ERROR: Test compilation failed!
    exit /b 1
)
echo     OK: test_memory_bridge.obj

echo.
echo ============================================================================
echo Build Complete
echo ============================================================================
echo.
echo Output files:
dir /b "%OUT_DIR%\SovereignMemoryBridge.*" 2^>nul
dir /b "%OUT_DIR%\test_memory_bridge.obj" 2^>nul
echo.
echo Next: Link test executable with Titan libraries
echo.

endlocal
