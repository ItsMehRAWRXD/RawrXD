@echo off
REM ============================================================================
REM Fix #3 NHWC Layout Validation - Direct Build
REM Uses full path to cl.exe
REM ============================================================================

echo ============================================================================
echo Fix #3 NHWC Layout - Direct Validation Build
echo ============================================================================
echo.

REM Full path to compiler
set CL_PATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe

REM Check if compiler exists
echo Checking compiler at: %CL_PATH%
if not exist "%CL_PATH%" (
    echo ERROR: Compiler not found!
    pause
    exit /b 1
)
echo Compiler found: OK
echo.

REM Directories
set SRC_DIR=d:\RawrXD\src\benchmark
set MEMORY_DIR=d:\RawrXD\src\memory
set OBJ_DIR=d:\RawrXD\obj\benchmark
set BIN_DIR=d:\RawrXD\bin

REM Create directories
if not exist %OBJ_DIR% mkdir %OBJ_DIR%
if not exist %BIN_DIR% mkdir %BIN_DIR%

echo [1/3] Building Fix3_NHWC_Benchmark.cpp...
echo.

REM Set up include paths
set VC_INC=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include
set WIN_SDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt
set WIN_SDK_UM=C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um
set WIN_SDK_SHARED=C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared

"%CL_PATH%" /nologo /W4 /EHsc /O2 /Zi /MD /arch:AVX512 /Fe"%BIN_DIR%\Fix3_NHWC_Benchmark.exe" ^
    "%SRC_DIR%\Fix3_NHWC_Benchmark.cpp" ^
    /I"%MEMORY_DIR%" ^
    /I"d:\RawrXD\include" ^
    /I"%VC_INC%" ^
    /I"%WIN_SDK_INC%" ^
    /I"%WIN_SDK_UM%" ^
    /I"%WIN_SDK_SHARED%" ^
    2>&1

if errorlevel 1 (
    echo ERROR: Compilation failed
    pause
    exit /b 1
)

echo.
echo [2/3] Build successful! Running benchmark...
echo.

"%BIN_DIR%\Fix3_NHWC_Benchmark.exe" > "%OBJ_DIR%\benchmark_results.txt" 2>&1

if errorlevel 1 (
    echo ERROR: Benchmark failed
    type "%OBJ_DIR%\benchmark_results.txt"
    pause
    exit /b 1
)

type "%OBJ_DIR%\benchmark_results.txt"
echo.

echo [3/3] Saving results...
copy /Y "%OBJ_DIR%\benchmark_results.txt" "d:\RawrXD\FIX3_NHWC_BENCHMARK_RESULTS.txt" >nul
echo.

echo ============================================================================
echo Validation Complete
echo ============================================================================
echo.
echo Results saved to: FIX3_NHWC_BENCHMARK_RESULTS.txt
echo.
pause
