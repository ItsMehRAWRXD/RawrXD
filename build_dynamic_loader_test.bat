@echo off
REM ============================================================================
REM build_dynamic_loader_test.bat
REM Build and run the Dynamic Model Loader test harness
REM ============================================================================

echo === RawrXD Dynamic Model Loader - Build Test ===

set VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231
set INCLUDE=%VS_PATH%\include;%INCLUDE%
set LIB=%VS_PATH%\lib\x64;%LIB%
set PATH=%VS_PATH%\bin\Hostx64\x64;%PATH%

set SRC_DIR=d:\rawrxd\src
set TEST_DIR=d:\rawrxd\tests
set OUT_DIR=d:\rawrxd\build_test

if not exist %OUT_DIR% mkdir %OUT_DIR%

echo Compiling dynamic_model_loader.cpp...
cl.exe /std:c++17 /EHsc /O2 /W3 /nologo ^
    /I %SRC_DIR% ^
    /I d:\rawrxd\src ^
    /D NOMINMAX ^
    /D WIN32_LEAN_AND_MEAN ^
    /Fo%OUT_DIR%\dynamic_model_loader.obj ^
    /c %SRC_DIR%\dynamic_model_loader.cpp

if errorlevel 1 (
    echo FAILED: dynamic_model_loader.cpp compilation
    exit /b 1
)

echo Compiling test_dynamic_loader.cpp...
cl.exe /std:c++17 /EHsc /O2 /W3 /nologo ^
    /I %SRC_DIR% ^
    /I d:\rawrxd\src ^
    /D NOMINMAX ^
    /D WIN32_LEAN_AND_MEAN ^
    /Fo%OUT_DIR%\test_dynamic_loader.obj ^
    /c %TEST_DIR%\test_dynamic_loader.cpp

if errorlevel 1 (
    echo FAILED: test_dynamic_loader.cpp compilation
    exit /b 1
)

echo Linking test executable...
link.exe /SUBSYSTEM:CONSOLE /OUT:%OUT_DIR%\test_dynamic_loader.exe ^
    %OUT_DIR%\dynamic_model_loader.obj ^
    %OUT_DIR%\test_dynamic_loader.obj ^
    kernel32.lib user32.lib psapi.lib

if errorlevel 1 (
    echo FAILED: Linking test executable
    exit /b 1
)

echo.
echo === Build Successful ===
echo Running test...
echo.

set RAWRXD_TINY_MODEL_PATH=F:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf
%OUT_DIR%\test_dynamic_loader.exe

if errorlevel 1 (
    echo.
    echo TEST FAILED
    exit /b 1
)

echo.
echo TEST PASSED
echo.
pause
