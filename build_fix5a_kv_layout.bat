@echo off
setlocal

REM ============================================================================
REM Fix 5A Build Script: KV Cache Layout Rewrite
REM Target: 2x performance gain from cache locality
REM ============================================================================

call "%ProgramFiles%\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

if errorlevel 1 (
    echo VS environment failed
    exit /b 1
)

echo ============================================================================
echo Fix 5A: KV Cache Layout Rewrite Build
echo ============================================================================
echo.

echo Compiler:
where cl
echo.
echo Windows SDK:
echo %WindowsSdkDir%
echo.

REM Create build directory
if not exist "bin" mkdir "bin"

echo [1/3] Compiling KV Cache Layout...
cl ^
    /O2 ^
    /std:c++20 ^
    /EHsc ^
    /arch:AVX512 ^
    /I src ^
    /c src\memory\RawrXD_KVCache_Layout.cpp ^
    /Fo:bin\RawrXD_KVCache_Layout.obj

if errorlevel 1 (
    echo ERROR: KV Cache compilation failed
    exit /b 1
)
echo     OK: RawrXD_KVCache_Layout.obj

echo.
echo [2/3] Compiling Deterministic Performance Mode...
cl ^
    /O2 ^
    /std:c++20 ^
    /EHsc ^
    /arch:AVX512 ^
    /I src ^
    /c src\runtime\RawrXD_DeterministicPerformance.cpp ^
    /Fo:bin\RawrXD_DeterministicPerformance.obj

if errorlevel 1 (
    echo ERROR: Deterministic performance compilation failed
    exit /b 1
)
echo     OK: RawrXD_DeterministicPerformance.obj

echo.
echo [3/3] Creating library...
lib /OUT:bin\RawrXD_Fix5A.lib ^
    bin\RawrXD_KVCache_Layout.obj ^
    bin\RawrXD_DeterministicPerformance.obj

if errorlevel 1 (
    echo ERROR: Library creation failed
    exit /b 1
)
echo     OK: RawrXD_Fix5A.lib

echo.
echo ============================================================================
echo Fix 5A Build Complete
echo ============================================================================
echo.
echo Artifacts:
echo   bin\RawrXD_Fix5A.lib
echo.
echo Next steps:
echo   1. Run validation: bin\test_fix5a_kv_cache.exe --verify-alignment
echo   2. Run benchmark: bin\test_fix5a_kv_cache.exe --run-benchmark
echo   3. Verify 2x performance gain vs legacy layout
echo.
