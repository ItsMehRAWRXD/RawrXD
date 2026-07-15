@echo off
setlocal EnableDelayedExpansion

echo ============================================
echo RawrXD Validation Suite - Complete Build
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

echo [1/8] Found VS at: %VS_PATH%

:: Find MSVC version
for /f "delims=" %%i in ('dir /b /ad "%VS_PATH%\VC\Tools\MSVC\" 2^>nul ^| sort /r') do (
    set "MSVC_VER=%%i"
    goto :found_msvc
)
:found_msvc
echo [2/8] Found MSVC version: %MSVC_VER%

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

echo [3/8] Building MASM kernels...
echo.

:: Build Q4_0 kernel
cd src\validation\kernels\masm
echo Building q4_0_dequant.asm...
"%ML64%" /c /W3 /nologo /Fo q4_0_dequant.obj q4_0_dequant.asm
if errorlevel 1 (
    echo ERROR: Failed to assemble q4_0_dequant.asm
    exit /b 1
)
echo   [OK] q4_0_dequant.obj

:: Build SiLU kernel
echo Building silu_activation_avx512.asm...
"%ML64%" /c /W3 /nologo /Fo silu_activation_avx512.obj silu_activation_avx512.asm
if errorlevel 1 (
    echo WARNING: Failed to assemble silu_activation_avx512.asm
) else (
    echo   [OK] silu_activation_avx512.obj
)

echo.
echo [4/8] Building validation tests...
echo.

cd ..

:: Build Q4_0 differential test
echo Building q4_0_differential_test.cpp...
"%CL%" /std:c++17 /EHsc /O2 /I"%~dp0\3rdparty\ggml\include" /Fe:q4_0_differential_test.exe q4_0_differential_test.cpp masm\q4_0_dequant.obj /link
if errorlevel 1 (
    echo WARNING: Failed to build q4_0_differential_test.exe
) else (
    echo   [OK] q4_0_differential_test.exe
)

:: Build llama comparison test
echo Building q4_0_llama_comparison.cpp...
"%CL%" /std:c++17 /EHsc /O2 /I"%~dp0\3rdparty\ggml\include" /I"%~dp0\3rdparty\ggml\src" /Fe:q4_0_llama_comparison.exe q4_0_llama_comparison.cpp "%~dp0\3rdparty\ggml\src\ggml-quants.c" "%~dp0\3rdparty\ggml\src\ggml.c" masm\q4_0_dequant.obj /link
if errorlevel 1 (
    echo WARNING: Failed to build q4_0_llama_comparison.exe
) else (
    echo   [OK] q4_0_llama_comparison.exe
)

cd ..

echo.
echo [5/8] Building GUI applications...
echo.

cd src\win32app

:: Build Minimal GUI
echo Building RawrXD_GUI_Minimal.cpp...
"%CL%" /EHsc /O2 /std:c++17 /DUNICODE /D_UNICODE /Fe:RawrXD_GUI_Minimal.exe RawrXD_GUI_Minimal.cpp /link user32.lib gdi32.lib comctl32.lib shell32.lib ole32.lib comdlg32.lib
if errorlevel 1 (
    echo ERROR: Failed to build RawrXD_GUI_Minimal.exe
    exit /b 1
)
echo   [OK] RawrXD_GUI_Minimal.exe

cd ..\..

echo.
echo [6/8] Building test suite...
echo.

cd src\tests

:: Build inference routing test
echo Building inference_routing_test.cpp...
"%CL%" /EHsc /O2 /std:c++17 /Fe:RawrXD-InferenceRoutingTest.exe inference_routing_test.cpp /link
if errorlevel 1 (
    echo WARNING: Failed to build RawrXD-InferenceRoutingTest.exe
) else (
    echo   [OK] RawrXD-InferenceRoutingTest.exe
)

cd ..\..

echo.
echo [7/8] Running tests...
echo.

:: Run inference routing tests
cd src\tests
if exist RawrXD-InferenceRoutingTest.exe (
    echo Running inference routing tests...
    RawrXD-InferenceRoutingTest.exe
    if errorlevel 1 (
        echo WARNING: Some tests failed
    ) else (
        echo   [OK] All tests passed
    )
)
cd ..\..

echo.
echo [8/8] Creating distribution package...
echo.

:: Create dist directory
if not exist dist mkdir dist
if not exist dist\bin mkdir dist\bin

:: Copy executables
copy /Y src\win32app\RawrXD_GUI_Minimal.exe dist\bin\RawrXD.exe >nul
echo   [OK] Copied RawrXD.exe

if exist src\tests\RawrXD-InferenceRoutingTest.exe (
    copy /Y src\tests\RawrXD-InferenceRoutingTest.exe dist\bin\ >nul
    echo   [OK] Copied RawrXD-InferenceRoutingTest.exe
)

if exist src\validation\q4_0_llama_comparison.exe (
    copy /Y src\validation\q4_0_llama_comparison.exe dist\bin\ >nul
    echo   [OK] Copied q4_0_llama_comparison.exe
)

echo.
echo ============================================
echo BUILD COMPLETE
echo ============================================
echo.
echo Built executables:
echo   - RawrXD_GUI_Minimal.exe (Main GUI)
echo   - RawrXD-InferenceRoutingTest.exe (Tests)
echo   - q4_0_llama_comparison.exe (Validation)
echo.
echo Distribution: dist\bin\
echo.
echo Next steps:
echo   1. Run dist\bin\RawrXD.exe
echo   2. Run dist\bin\q4_0_llama_comparison.exe
echo   3. Create ZIP package with package\create_distribution.ps1
echo.

pause
