@echo off
setlocal

echo ============================================
echo Q4_0 llama.cpp Comparison Build
echo ============================================
echo.

:: Find VS2022
set "VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise"
if not exist "%VS_PATH%" (
    set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
)
if not exist "%VS_PATH%" (
    set "VS_PATH=C:\VS2022Enterprise"
)

if not exist "%VS_PATH%" (
    echo ERROR: Visual Studio not found
    exit /b 1
)

:: Find MSVC version
for /f "delims=" %%i in ('dir /b /ad "%VS_PATH%\VC\Tools\MSVC\" 2^>nul ^| sort /r') do (
    set "MSVC_VER=%%i"
    goto :found_msvc
)
:found_msvc

set "MSVC_ROOT=%VS_PATH%\VC\Tools\MSVC\%MSVC_VER%"
set "ML64=%MSVC_ROOT%\bin\Hostx64\x64\ml64.exe"
set "CL=%MSVC_ROOT%\bin\Hostx64\x64\cl.exe"

:: Find Windows SDK
set "SDK_PATH=C:\Program Files (x86)\Windows Kits\10"
set "SDK_VER=10.0.22621.0"

:: Set up paths
set "INCLUDE=%MSVC_ROOT%\include;%SDK_PATH%\Include\%SDK_VER%\ucrt;%SDK_PATH%\Include\%SDK_VER%\shared;%SDK_PATH%\Include\%SDK_VER%\um"
set "LIB=%MSVC_ROOT%\lib\x64;%SDK_PATH%\Lib\%SDK_VER%\ucrt\x64;%SDK_PATH%\Lib\%SDK_VER%\um\x64"

cd /d "%~dp0"

echo [1/3] Assembling Q4_0 kernel...
cd kernels\masm
"%ML64%" /c /W3 /nologo /Fo q4_0_dequant.obj q4_0_dequant.asm
if errorlevel 1 (
    echo ERROR: Failed to assemble q4_0_dequant.asm
    exit /b 1
)
echo   [OK] q4_0_dequant.obj
cd ..\..

echo.
echo [2/3] Building comparison test...
"%CL%" /std:c++17 /EHsc /O2 /I"..\..\3rdparty\ggml\include" /I"..\..\3rdparty\ggml\src" /Fe:q4_0_llama_comparison.exe q4_0_llama_comparison.cpp "..\..\3rdparty\ggml\src\ggml-quants.c" "..\..\3rdparty\ggml\src\ggml.c" kernels\masm\q4_0_dequant.obj /link
if errorlevel 1 (
    echo ERROR: Failed to build q4_0_llama_comparison.exe
    exit /b 1
)
echo   [OK] q4_0_llama_comparison.exe

echo.
echo [3/3] Running test...
q4_0_llama_comparison.exe

echo.
echo ============================================
echo Build and Test Complete
echo ============================================

pause
