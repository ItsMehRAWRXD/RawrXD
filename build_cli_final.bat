@echo off
:: Build script for minimal CLI using MSVC
:: Links against the actual kernel .lib files

setlocal EnableDelayedExpansion

echo ==============================================================================
echo Sovereign CLI Minimal Build - Phase 7C.2
echo ==============================================================================
echo.

:: Create build directory
if not exist "d:\rawrxd\build_cli" mkdir "d:\rawrxd\build_cli"

:: MSVC paths
set MSVC_ROOT=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231
set WINSDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0
set WINSDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0

echo Using MSVC: %MSVC_ROOT%
echo.

:: Build CLI main
echo [1/2] Compiling cli_minimal.cpp...

"%MSVC_ROOT%\bin\Hostx64\x64\cl.exe" /std:c++17 /O2 /arch:AVX2 /DNDEBUG /D_WIN32 /EHsc /W3 /nologo /c ^
    /I"%MSVC_ROOT%\include" ^
    /I"%WINSDK_INC%\um" ^
    /I"%WINSDK_INC%\shared" ^
    /I"%WINSDK_INC%\ucrt" ^
    "d:\rawrxd\cli_minimal.cpp" ^
    /Fo"d:\rawrxd\build_cli\cli_minimal.obj"

if errorlevel 1 (
    echo FAILED: cli_minimal.cpp compilation
    exit /b 1
)
echo ^> cli_minimal.obj compiled
echo.

:: Link with kernel libraries
echo [2/2] Linking SovereignCLI_Minimal.exe...
echo.

"%MSVC_ROOT%\bin\Hostx64\x64\link.exe" ^
    /OUT:"d:\rawrxd\build_cli\SovereignCLI_Minimal.exe" ^
    /SUBSYSTEM:CONSOLE /MACHINE:X64 /nologo ^
    "d:\rawrxd\build_cli\cli_minimal.obj" ^
    "d:\src\asm\Sovereign_Legacy_Kernels.lib" ^
    "d:\src\asm\Sovereign_Intrinsics.lib" ^
    "d:\src\asm\Sovereign_RMSNorm.lib" ^
    "d:\src\asm\Sovereign_ResidualAdd.lib" ^
    "d:\src\asm\Sovereign_RoPE.lib" ^
    "d:\src\asm\Sovereign_LayerNorm.lib" ^
    "d:\src\asm\Sovereign_Q4K_Dequant.lib" ^
    kernel32.lib user32.lib ucrt.lib vcruntime.lib msvcrt.lib

if errorlevel 1 (
    echo FAILED: Linking
    exit /b 1
)

echo.
echo ==============================================================================
echo BUILD SUCCESSFUL
echo ==============================================================================
echo.
echo Output: d:\rawrxd\build_cli\SovereignCLI_Minimal.exe
echo.
echo Run with:
echo   d:\rawrxd\build_cli\SovereignCLI_Minimal.exe test
echo   d:\rawrxd\build_cli\SovereignCLI_Minimal.exe info
echo ==============================================================================
