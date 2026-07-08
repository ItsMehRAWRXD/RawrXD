@echo off
REM Build and test the complete inference pipeline
setlocal

set "CL_EXE=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe"
set "LINK_EXE=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe"

set "SDK_ROOT=C:\Program Files (x86)\Windows Kits\10"
set "SDK_VER=10.0.22621.0"
set "MSVC_ROOT=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231"

set "INCLUDE=%MSVC_ROOT%\include;%SDK_ROOT%\Include\%SDK_VER%\ucrt;%SDK_ROOT%\Include\%SDK_VER%\um;%SDK_ROOT%\Include\%SDK_VER%\shared"
set "LIB=%MSVC_ROOT%\lib\x64;%SDK_ROOT%\Lib\%SDK_VER%\ucrt\x64;%SDK_ROOT%\Lib\%SDK_VER%\um\x64"

set "SRC_DIR=d:\rawrxd\src"
set "BUILD_DIR=d:\rawrxd\build_inference"

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [1/8] Compiling inference engine...
"%CL_EXE%" /EHsc /std:c++17 /W4 /O2 /I"%SRC_DIR%" /I"%SRC_DIR%\inference" /Fo"%BUILD_DIR%\inference_engine.obj" /c "%SRC_DIR%\inference\inference_engine.cpp"
if errorlevel 1 (
    echo ERROR: Inference engine compilation failed
    exit /b 1
)

echo [2/8] Compiling GGUF loader...
"%CL_EXE%" /EHsc /std:c++17 /W4 /O2 /I"%SRC_DIR%" /Fo"%BUILD_DIR%\gguf_loader.obj" /c "%SRC_DIR%\gguf_loader.cpp"
if errorlevel 1 (
    echo ERROR: GGUF loader compilation failed
    exit /b 1
)

echo [3/8] Compiling inference pipeline test...
"%CL_EXE%" /EHsc /std:c++17 /W4 /O2 /I"%SRC_DIR%" /I"%SRC_DIR%\inference" /Fo"%BUILD_DIR%\inference_pipeline_test.obj" /c "%SRC_DIR%\inference\inference_pipeline_test.cpp"
if errorlevel 1 (
    echo ERROR: Test compilation failed
    exit /b 1
)

echo [4/8] Linking inference test executable...
"%LINK_EXE%" /SUBSYSTEM:CONSOLE /LARGEADDRESSAWARE:NO /OUT:"%BUILD_DIR%\inference_pipeline_test.exe" "%BUILD_DIR%\inference_engine.obj" "%BUILD_DIR%\gguf_loader.obj" "%BUILD_DIR%\inference_pipeline_test.obj" kernel32.lib user32.lib
if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)

echo [5/8] Running inference pipeline tests...
"%BUILD_DIR%\inference_pipeline_test.exe"
if errorlevel 1 (
    echo WARNING: Some tests failed
) else (
    echo All tests passed!
)

echo.
echo === Inference Pipeline Build Complete ===
echo Location: %BUILD_DIR%
echo.
echo Executables:
echo   - inference_pipeline_test.exe
echo.

pause