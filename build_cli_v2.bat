@echo off
:: Build script for minimal CLI using MSVC
:: Links against the actual kernel .lib files

setlocal EnableDelayedExpansion

echo ==============================================================================
echo Sovereign CLI Minimal Build - Phase 7C.2
echo ==============================================================================
echo.

:: Configuration
set BUILD_DIR=d:\rawrxd\build_cli
set ASM_DIR=d:\src\asm

:: Full paths to MSVC tools
set CXX=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe
set LINK=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe

:: MSVC and Windows SDK paths
set MSVC_INC=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include
set WINSDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0
set WINSDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0

:: Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

:: Check compiler exists
if not exist "%CXX%" (
    echo ERROR: Compiler not found at %CXX%
    exit /b 1
)

echo Using compiler: %CXX%
echo Build directory: %BUILD_DIR%
echo.

:: Build CLI main - use delayed expansion to handle spaces in paths
echo [1/2] Compiling cli_minimal.cpp...

set COMPILE_CMD="%CXX%" /std:c++17 /O2 /arch:AVX2 /DNDEBUG /D_WIN32 /EHsc /W3 /nologo ^
    /I"%MSVC_INC%" ^
    /I"%WINSDK_INC%\um" ^
    /I"%WINSDK_INC%\shared" ^
    /I"%WINSDK_INC%\ucrt" ^
    "d:\rawrxd\cli_minimal.cpp" ^
    /Fo"%BUILD_DIR%\cli_minimal.obj" ^
    /c

%COMPILE_CMD%
if errorlevel 1 (
    echo FAILED: cli_minimal.cpp compilation
    exit /b 1
)
echo ^> cli_minimal.obj compiled
echo.

:: Link with kernel libraries
echo [2/2] Linking SovereignCLI_Minimal.exe...
echo Linking against kernel libraries in %ASM_DIR%
echo.

:: Use short paths to avoid space issues
for %%I in ("%BUILD_DIR%") do set BUILD_SHORT=%%~sI
for %%I in ("%ASM_DIR%") do set ASM_SHORT=%%~sI

echo Using short paths:
echo   Build: %BUILD_SHORT%
echo   ASM: %ASM_SHORT%
echo.

set LINK_CMD="%LINK%" /OUT:"%BUILD_SHORT%\SovereignCLI_Minimal.exe" ^
    /SUBSYSTEM:CONSOLE ^
    /MACHINE:X64 ^
    /LIBPATH:"%ASM_SHORT%" ^
    "%BUILD_SHORT%\cli_minimal.obj" ^
    "%ASM_SHORT%\Sovereign_Legacy_Kernels.lib" ^
    "%ASM_SHORT%\Sovereign_Intrinsics.lib" ^
    "%ASM_SHORT%\Sovereign_RMSNorm.lib" ^
    "%ASM_SHORT%\Sovereign_ResidualAdd.lib" ^
    "%ASM_SHORT%\Sovereign_RoPE.lib" ^
    "%ASM_SHORT%\Sovereign_LayerNorm.lib" ^
    "%ASM_SHORT%\Sovereign_Q4K_Dequant.lib" ^
    kernel32.lib user32.lib ucrt.lib vcruntime.lib msvcrt.lib

%LINK_CMD%

if errorlevel 1 (
    echo FAILED: Linking
    exit /b 1
)

echo.
echo ==============================================================================
echo BUILD SUCCESSFUL
echo ==============================================================================
echo.
echo Output: %BUILD_DIR%\SovereignCLI_Minimal.exe
echo.
echo Run with:
echo   %BUILD_DIR%\SovereignCLI_Minimal.exe test
echo   %BUILD_DIR%\SovereignCLI_Minimal.exe info
echo ==============================================================================
