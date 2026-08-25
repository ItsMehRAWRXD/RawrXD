@echo off
REM ============================================================================
REM Build Sovereign Engine — Dragon Lore Edition
REM Compiles: Chamber, ToroidalKVCache, PlasmaGovernor, SovereignOutOfCoreRuntime
REM           + existing OutOfCoreRuntime, GGMLBackend stubs
REM ============================================================================

echo [+] Sovereign Engine Build — kennyS Scope Edition
echo.

REM Setup VS2022 environment
if exist "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
) else (
    echo ERROR: Could not find vcvars64.bat
    exit /b 1
)

set SRC_DIR=%~dp0
set BUILD_DIR=%SRC_DIR%\sovereign_build

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM Compiler flags
set COMMON_FLAGS=/nologo /W4 /O2 /arch:AVX2 /EHsc /std:c++20 /D_CRT_SECURE_NO_WARNINGS
set INCLUDES=/I"%SRC_DIR%" /I"%SRC_DIR%\.." /I"%SRC_DIR%\..\..\include"

REM Source files
set SOURCES=^
    "%SRC_DIR%\OutOfCoreRuntime.cpp"^
    "%SRC_DIR%\Chamber.cpp"^
    "%SRC_DIR%\ToroidalKVCache.cpp"^
    "%SRC_DIR%\PlasmaGovernor.cpp"^
    "%SRC_DIR%\SovereignOutOfCoreRuntime.cpp"^
    "%SRC_DIR%\deep2_link_stubs.cpp"

echo Compiling Sovereign Engine components...
echo.

cl.exe %COMMON_FLAGS% %INCLUDES%^
    /Fe"%BUILD_DIR%\SovereignEngine.exe"^
    %SOURCES%^
    /link /SUBSYSTEM:CONSOLE

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [FAIL] BUILD FAILED
    exit /b %ERRORLEVEL%
)

echo.
echo [PASS] BUILD SUCCESSFUL
echo Executable: %BUILD_DIR%\SovereignEngine.exe
echo.
echo Components built:
echo   - Chamber (SM0-DSP clash detector)
echo   - ToroidalKVCache (infinite-context ring buffer)
echo   - PlasmaGovernor (R9700 thermal safety)
echo   - SovereignOutOfCoreRuntime (dual-backend orchestrator)
echo   - OutOfCoreRuntime (elastic residency)
echo.

exit /b 0
