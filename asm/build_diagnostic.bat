@echo off
:: Build Kernel Loading Diagnostic
::
:: Date: July 10, 2026

echo ============================================================================
echo Kernel Loading Diagnostic Build
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

:: Compiler flags
set CFLAGS=/EHsc /O2 /W3 /nologo /MD

echo [1/1] Compiling diagnose_kernel_loading.cpp...
"%CL%" %CFLAGS% /Fo"%OUT_DIR%\diagnose_kernel_loading.obj" /Fe"%OUT_DIR%\diagnose_kernel_loading.exe" "%SRC_DIR%\diagnose_kernel_loading.cpp"
if errorlevel 1 (
    echo ERROR: Compilation failed!
    exit /b 1
)
echo     OK: diagnose_kernel_loading.exe

echo.
echo ============================================================================
echo Build Complete
echo ============================================================================
echo.
echo Run the diagnostic with:
echo   %OUT_DIR%\diagnose_kernel_loading.exe
echo.
echo This will check:
echo   - Library file existence
echo   - Export table inspection
echo   - Direct kernel calls
echo.

endlocal
