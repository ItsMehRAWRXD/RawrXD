@echo off
:: Build Kernel Correctness Test
::
:: Date: July 10, 2026

echo ============================================================================
echo Kernel Correctness Test Build
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
set "LINK=%VS_TOOLS%\link.exe"

:: Include paths
set INCLUDES=/I"%SRC_DIR%"

:: Compiler flags
set CFLAGS=/EHsc /O2 /W3 /nologo /MD %INCLUDES%

:: Libraries to link
set LIBS="%SRC_DIR%\Sovereign_RMSNorm.lib" "%SRC_DIR%\Sovereign_LayerNorm.lib" "%SRC_DIR%\Sovereign_ResidualAdd.lib" "%SRC_DIR%\Sovereign_Intrinsics.lib" "%SRC_DIR%\Sovereign_Legacy_Kernels.lib" kernel32.lib user32.lib

echo [1/2] Compiling test_kernel_correctness.cpp...
"%CL%" %CFLAGS% /Fo"%OUT_DIR%\test_kernel_correctness.obj" "%SRC_DIR%\test_kernel_correctness.cpp"
if errorlevel 1 (
    echo ERROR: Compilation failed!
    exit /b 1
)
echo     OK: test_kernel_correctness.obj

echo.
echo [2/2] Linking test executable...
"%LINK%" /SUBSYSTEM:CONSOLE /NODEFAULTLIB:libcmt.lib /OUT:"%OUT_DIR%\test_kernel_correctness.exe" "%OUT_DIR%\test_kernel_correctness.obj" %LIBS%
if errorlevel 1 (
    echo ERROR: Link failed!
    exit /b 1
)
echo     OK: test_kernel_correctness.exe

echo.
echo ============================================================================
echo Build Complete
echo ============================================================================
echo.
echo Run the test with:
echo   %OUT_DIR%\test_kernel_correctness.exe
echo.

endlocal
