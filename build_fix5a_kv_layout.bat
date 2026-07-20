@echo off
REM ============================================================================
REM Fix 5A Build Script: KV Cache Layout Rewrite
REM Target: 2x performance gain from cache locality
REM ============================================================================

setlocal EnableDelayedExpansion

REM Configuration
set RAWRXD_ROOT=D:\RawrXD
set BUILD_DIR=%RAWRXD_ROOT%\build_fix5a
set CL_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe

echo ============================================================================
echo Fix 5A: KV Cache Layout Rewrite Build
echo ============================================================================
echo.

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM Compile KV Cache Layout
echo [1/4] Compiling KV Cache Layout...
"%CL_PATH%" /c /O2 /arch:AVX512 /EHsc /std:c++20 /I"%RAWRXD_ROOT%\src" ^
    /Fo"%BUILD_DIR%\RawrXD_KVCache_Layout.obj" ^
    "%RAWRXD_ROOT%\src\memory\RawrXD_KVCache_Layout.cpp"

if errorlevel 1 (
    echo ERROR: KV Cache compilation failed
    exit /b 1
)
echo     OK: RawrXD_KVCache_Layout.obj

REM Compile Deterministic Performance
echo.
echo [2/4] Compiling Deterministic Performance Mode...
"%CL_PATH%" /c /O2 /arch:AVX512 /EHsc /std:c++20 /I"%RAWRXD_ROOT%\src" ^
    /Fo"%BUILD_DIR%\RawrXD_DeterministicPerformance.obj" ^
    "%RAWRXD_ROOT%\src\runtime\RawrXD_DeterministicPerformance.cpp"

if errorlevel 1 (
    echo ERROR: Deterministic performance compilation failed
    exit /b 1
)
echo     OK: RawrXD_DeterministicPerformance.obj

REM Create static library
echo.
echo [3/4] Creating library...
lib /OUT:"%BUILD_DIR%\RawrXD_Fix5A.lib" ^
    "%BUILD_DIR%\RawrXD_KVCache_Layout.obj" ^
    "%BUILD_DIR%\RawrXD_DeterministicPerformance.obj"

if errorlevel 1 (
    echo ERROR: Library creation failed
    exit /b 1
)
echo     OK: RawrXD_Fix5A.lib

REM Build test harness
echo.
echo [4/4] Building test harness...
"%CL_PATH%" /O2 /arch:AVX512 /EHsc /std:c++20 /I"%RAWRXD_ROOT%\src" ^
    "%RAWRXD_ROOT%\tests\test_fix5a_kv_cache.cpp" ^
    "%BUILD_DIR%\RawrXD_Fix5A.lib" ^
    /Fe"%BUILD_DIR%\test_fix5a_kv_cache.exe"

if errorlevel 1 (
    echo ERROR: Test build failed
    exit /b 1
)
echo     OK: test_fix5a_kv_cache.exe

echo.
echo ============================================================================
echo Fix 5A Build Complete
echo ============================================================================
echo.
echo Artifacts:
echo   %BUILD_DIR%\RawrXD_Fix5A.lib
echo   %BUILD_DIR%\test_fix5a_kv_cache.exe
echo.
echo Next steps:
echo   1. Run validation: .\test_fix5a_kv_cache.exe --benchmark --deterministic-performance
echo   2. Verify 2x performance gain vs legacy layout
echo   3. Check pulse stability with validation gate
echo.

endlocal
