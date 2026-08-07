@echo off
REM Build script for Deep2 Phase 0 Smoketest
REM Tests: API server, GPU discovery, model management, full stack integration

echo Building Deep2 Phase 0 Smoketest...
echo.

REM Setup VS2022 environment
if exist "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
) else (
    echo ERROR: Could not find vcvars64.bat
    echo Attempting to use system default compiler...
)

set SRC_DIR=%~dp0
set BUILD_DIR=%SRC_DIR%\phase0_build

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo Compiling Deep2_Phase0_SmokeTest.cpp...
echo This tests the full Phase 0 backend binding stack.
echo.

cl.exe /nologo /W4 /O2 /arch:AVX2 /EHsc /std:c++20 ^
    /I"%SRC_DIR%" ^
    /I"%SRC_DIR%\.." ^
    /I"%SRC_DIR%\..\..\include" ^
    /I"%SRC_DIR%\..\sampling" ^
    /I"%SRC_DIR%\gpu" ^
    /D_CRT_SECURE_NO_WARNINGS ^
    /DDEEP2_ENABLE_GPU ^
    /Fe"%BUILD_DIR%\Deep2_Phase0_SmokeTest.exe" ^
    "%SRC_DIR%\Deep2_Phase0_SmokeTest.cpp" ^
    /link /SUBSYSTEM:CONSOLE /LARGEADDRESSAWARE

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo BUILD FAILED
    echo.
    echo Common issues:
    echo   - Missing headers: Check include paths
    echo   - Missing libs: Link against Deep2 libraries
    echo   - GPU support: Ensure Vulkan SDK is installed
    exit /b %ERRORLEVEL%
)

echo.
echo BUILD SUCCESSFUL
echo Executable: %BUILD_DIR%\Deep2_Phase0_SmokeTest.exe
echo.
echo Running Phase 0 smoketest...
echo This will validate:
echo   - API server endpoints
echo   - GPU device discovery (R9700, 7800XT)
echo   - Multi-GPU scheduler
echo   - Model scanner
echo   - Execution graph
echo   - Runtime planner
echo   - Autonomous systems
echo   - Full stack integration
echo.

"%BUILD_DIR%\Deep2_Phase0_SmokeTest.exe"

exit /b %ERRORLEVEL%
