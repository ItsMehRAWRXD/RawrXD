@echo off
REM ============================================================================
REM test_softmax_minimal.bat - Minimal Softmax Test
REM ============================================================================

set "MSVC_ROOT=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231"
set "WIN_SDK_ROOT=C:\Program Files (x86)\Windows Kits\10"
set "SDK_VER=10.0.22621.0"

set "INCLUDE=%MSVC_ROOT%\include;%WIN_SDK_ROOT%\Include\%SDK_VER%\ucrt;%WIN_SDK_ROOT%\Include\%SDK_VER%\shared;%WIN_SDK_ROOT%\Include\%SDK_VER%\um"
set "LIB=%MSVC_ROOT%\lib\x64;%MSVC_ROOT%\lib\onecore\x64;%WIN_SDK_ROOT%\Lib\%SDK_VER%\ucrt\x64;%WIN_SDK_ROOT%\Lib\%SDK_VER%\um\x64"
set "PATH=%MSVC_ROOT%\bin\Hostx64\x64;%WIN_SDK_ROOT%\bin\%SDK_VER%\x64;%PATH%"

echo [TEST] Compiling minimal Softmax test...
"%MSVC_ROOT%\bin\Hostx64\x64\cl.exe" /EHsc /Fe:test_softmax_minimal.exe test_softmax_minimal.cpp build\kernels\silu_activation_avx512.obj build\kernels\rmsnorm_forward_avx2.obj build\kernels\softmax_forward_avx2.obj

if errorlevel 1 (
    echo [ERROR] Compilation failed
    exit /b 1
)

echo [TEST] Running minimal Softmax test...
test_softmax_minimal.exe