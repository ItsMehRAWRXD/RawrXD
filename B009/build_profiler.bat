@echo off
REM Build script for B009 Negative Space Profiler
REM Uses VS2022 Enterprise x64 Native Tools

echo ==========================================
echo B009 Negative Space Profiler Build Script
echo ==========================================

REM Initialize VS2022 x64 environment
set "VSWHERE=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VSWHERE%" (
    echo ERROR: VS2022 vcvars64.bat not found at %VSWHERE%
    exit /b 1
)

call "%VSWHERE%"
if errorlevel 1 (
    echo ERROR: Could not initialize VS2022 x64 environment.
    exit /b 1
)

echo.
echo [1/3] Assembling NegativeSpaceProfiler.asm...
ml64.exe /c /Zi /FoNegativeSpaceProfiler.obj NegativeSpaceProfiler.asm
if errorlevel 1 (
    echo ERROR: Assembly failed!
    exit /b 1
)
echo     OK: NegativeSpaceProfiler.obj created.

echo.
echo [2/3] Compiling C++ test harness...
cl.exe /O2 /EHsc /Zi /W4 /FeB009_ProfilerTest.exe B009_ProfilerTest.cpp NegativeSpaceProfiler.obj
if errorlevel 1 (
    echo ERROR: C++ compilation failed!
    exit /b 1
)
echo     OK: B009_ProfilerTest.exe created.

echo.
echo [3/3] Running profiler test...
echo ==========================================
B009_ProfilerTest.exe

echo.
echo ==========================================
echo Build and run complete.
pause
