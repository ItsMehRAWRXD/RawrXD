@echo off
REM ============================================================================
REM build_masm_benchmarks.bat - Build MASM Benchmark Integration
REM ============================================================================
REM Builds the MASM kernels and integrates them into telemetry_validation
REM ============================================================================

echo [BUILD] MASM Benchmark Integration
echo ====================================

set "MSVC_ROOT=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231"
set "WIN_SDK_ROOT=C:\Program Files (x86)\Windows Kits\10"
set "SDK_VER=10.0.22621.0"

echo [BUILD] MSVC: %MSVC_ROOT%
echo [BUILD] SDK: %WIN_SDK_ROOT%\%SDK_VER%

REM Set up environment
set "INCLUDE=%MSVC_ROOT%\include;%WIN_SDK_ROOT%\Include\%SDK_VER%\ucrt;%WIN_SDK_ROOT%\Include\%SDK_VER%\shared;%WIN_SDK_ROOT%\Include\%SDK_VER%\um"
set "LIB=%MSVC_ROOT%\lib\x64;%MSVC_ROOT%\lib\onecore\x64;%WIN_SDK_ROOT%\Lib\%SDK_VER%\ucrt\x64;%WIN_SDK_ROOT%\Lib\%SDK_VER%\um\x64"
set "PATH=%MSVC_ROOT%\bin\Hostx64\x64;%WIN_SDK_ROOT%\bin\%SDK_VER%\x64;%PATH%"

echo [BUILD] INCLUDE set
echo [BUILD] LIB set

REM Create build directory
if not exist "build\kernels" mkdir build\kernels

echo.
echo [BUILD] Assembling MASM kernels...
echo.

REM Assemble SiLU kernel
"%MSVC_ROOT%\bin\Hostx64\x64\ml64.exe" /c /W3 /nologo /Zi /Fo build\kernels\silu_activation_avx512.obj src\validation\kernels\masm\silu_activation_avx512.asm
if errorlevel 1 (
    echo [ERROR] Failed to assemble silu_activation_avx512.asm
    exit /b 1
)
echo [BUILD] silu_activation_avx512.obj assembled

REM Assemble RMSNorm kernel
"%MSVC_ROOT%\bin\Hostx64\x64\ml64.exe" /c /W3 /nologo /Zi /Fo build\kernels\rmsnorm_forward_avx2.obj src\validation\kernels\masm\rmsnorm_forward_avx2.asm
if errorlevel 1 (
    echo [ERROR] Failed to assemble rmsnorm_forward_avx2.asm
    exit /b 1
)
echo [BUILD] rmsnorm_forward_avx2.obj assembled

echo.
echo [BUILD] Compiling telemetry_validation...
echo.

REM Compile telemetry_validation.cpp
"%MSVC_ROOT%\bin\Hostx64\x64\cl.exe" /std:c++latest /EHsc /W3 /nologo /DWIN32 /D_WINDOWS /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /D__AVX2__ ^
    /I"src\validation" /I"src\validation\kernels" ^
    /c src\validation\telemetry_validation.cpp /Fo"build\telemetry_validation.obj"
if errorlevel 1 (
    echo [ERROR] Failed to compile telemetry_validation.cpp
    exit /b 1
)

echo.
echo [BUILD] Linking...
echo.

REM Link
"%MSVC_ROOT%\bin\Hostx64\x64\link.exe" build\telemetry_validation.obj build\kernels\silu_activation_avx512.obj build\kernels\rmsnorm_forward_avx2.obj ^
    user32.lib kernel32.lib /OUT:"build\telemetry_validation.exe"
if errorlevel 1 (
    echo [ERROR] Link failed
    exit /b 1
)

echo.
echo [BUILD] ============================================
echo [BUILD] Build successful!
echo [BUILD] Output: build\telemetry_validation.exe
echo [BUILD] ============================================
echo.
echo [RUN] To execute the benchmarks:
echo [RUN]   build\telemetry_validation.exe