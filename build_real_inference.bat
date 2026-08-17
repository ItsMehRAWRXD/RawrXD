@echo off
REM Build script for real inference implementation
REM ============================================================================

setlocal enabledelayedexpansion

echo Building RawrXD Real Inference Implementation...
echo.

REM Set up Visual Studio environment
if exist "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
) else (
    echo ERROR: Could not find Visual Studio 2022 vcvars64.bat
    exit /b 1
)

REM Create output directory
if not exist "build_real_inference" mkdir build_real_inference
cd build_real_inference

echo Compiling GGML Fallback...
cl.exe /c /W3 /O2 /nologo /EHsc /std:c++17 /I..\include /I..\src ..
\src\ai\ggml_fallback.h 2>nul
if errorlevel 1 (
    echo Note: ggml_fallback.h is a header-only library
)

echo.
echo Compiling Real Inference Implementation...
cl.exe /c /W3 /O2 /nologo /EHsc /std:c++17 /I..\include /I..\src ..\src\ai\ai_model_caller_real_complete.cpp /Fo:ai_model_caller_real_complete.obj
if errorlevel 1 (
    echo ERROR: Failed to compile ai_model_caller_real_complete.cpp
    exit /b 1
)
echo   OK: ai_model_caller_real_complete.obj

cl.exe /c /W3 /O2 /nologo /EHsc /std:c++17 /I..\include /I..\src ..\src\inference\inference_engine_real.cpp /Fo:inference_engine_real.obj
if errorlevel 1 (
    echo ERROR: Failed to compile inference_engine_real.cpp
    exit /b 1
)
echo   OK: inference_engine_real.obj

echo.
echo Compiling Test Program...
cl.exe /c /W3 /O2 /nologo /EHsc /std:c++17 /I..\include /I..\src ..\src\ai\test_inference_real.cpp /Fo:test_inference_real.obj
if errorlevel 1 (
    echo ERROR: Failed to compile test_inference_real.cpp
    exit /b 1
)
echo   OK: test_inference_real.obj

echo.
echo Linking Test Executable...
link.exe /nologo /out:test_inference_real.exe test_inference_real.obj ai_model_caller_real_complete.obj inference_engine_real.obj
if errorlevel 1 (
    echo ERROR: Failed to link test executable
    exit /b 1
)
echo   OK: test_inference_real.exe

echo.
echo Running Tests...
test_inference_real.exe
if errorlevel 1 (
    echo ERROR: Tests failed
    exit /b 1
)

echo.
echo Creating Static Library...
lib.exe /nologo /out:real_inference.lib ai_model_caller_real_complete.obj inference_engine_real.obj
if errorlevel 1 (
    echo ERROR: Failed to create static library
    exit /b 1
)
echo   OK: real_inference.lib

echo.
echo ============================================================================
echo Build completed successfully!
echo.
echo Outputs:
echo   - test_inference_real.exe  (Test executable)
echo   - real_inference.lib       (Static library)
echo   - *.obj                      (Object files)
echo ============================================================================

cd ..

endlocal
