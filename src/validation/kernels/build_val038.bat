@echo off
setlocal EnableDelayedExpansion

echo ============================================================================
echo VAL-038 Build Script (VS18 Enterprise)
echo ============================================================================

set VS18=C:\Program Files\Microsoft Visual Studio\18\Enterprise
set WINSDK=C:\Program Files (x86)\Windows Kits\10
set WINSDK_VER=10.0.26100.0

REM Initialize VS environment
call "%VS18%\VC\Auxiliary\Build\vcvars64.bat"

REM Ensure SDK paths are in INCLUDE and LIB
set INCLUDE=%WINSDK%\Include\%WINSDK_VER%\um;%WINSDK%\Include\%WINSDK_VER%\shared;%WINSDK%\Include\%WINSDK_VER%\ucrt;%INCLUDE%
set LIB=%WINSDK%\Lib\%WINSDK_VER%\um\x64;%WINSDK%\Lib\%WINSDK_VER%\ucrt\x64;%LIB%

echo.
echo [1/4] Assembling TreeAttention_Fused_VAL038.asm...
ml64 /c /W3 /nologo /Zi /Fo masm\TreeAttention_Fused_VAL038.obj masm\TreeAttention_Fused_VAL038.asm
if errorlevel 1 (
    echo ERROR: Assembly failed
    exit /b 1
)
echo OK: masm\TreeAttention_Fused_VAL038.obj

echo.
echo [2/4] Assembling softmax_lut_avx512.asm...
ml64 /c /W3 /nologo /Zi /Fo masm\softmax_lut_avx512.obj masm\softmax_lut_avx512.asm
if errorlevel 1 (
    echo ERROR: Assembly failed
    exit /b 1
)
echo OK: masm\softmax_lut_avx512.obj

echo.
echo [3/4] Compiling VAL038_Benchmark_Harness.cpp...
cl /c /W4 /O2 /nologo /Zi /EHsc /arch:AVX512 /Fo VAL038_Benchmark_Harness.obj VAL038_Benchmark_Harness.cpp
if errorlevel 1 (
    echo ERROR: Compilation failed
    exit /b 1
)
echo OK: VAL038_Benchmark_Harness.obj

echo.
echo [4/4] Linking...
link /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /LARGEADDRESSAWARE:NO /OUT:VAL038_Benchmark_Harness.exe VAL038_Benchmark_Harness.obj masm\TreeAttention_Fused_VAL038.obj masm\softmax_lut_avx512.obj kernel32.lib libucrt.lib legacy_stdio_definitions.lib
if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)
echo OK: VAL038_Benchmark_Harness.exe

echo.
echo ============================================================================
echo Build Complete
echo ============================================================================
echo.
echo Run with: VAL038_Benchmark_Harness.exe