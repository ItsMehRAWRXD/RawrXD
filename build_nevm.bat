@echo off
::============================================================================
:: build_nevm.bat
:: RawrXD N-EVM Build Script
:: Builds the complete Neural Execution Virtual Machine
::============================================================================

setlocal EnableDelayedExpansion

:: Tool paths
set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set CL=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe

:: Directories
set SRC_DIR=d:\RawrXD\src\nevm
set OBJ_DIR=d:\RawrXD\build\nevm\obj
set BIN_DIR=d:\RawrXD\build\nevm\bin
set INC_DIR=d:\RawrXD\src\nevm

:: Create directories
if not exist %OBJ_DIR% mkdir %OBJ_DIR%
if not exist %BIN_DIR% mkdir %BIN_DIR%

echo ============================================
echo RawrXD N-EVM Build Pipeline
echo ============================================
echo.

:: Clean previous build
echo Cleaning previous build...
if exist %OBJ_DIR%\*.obj del /Q %OBJ_DIR%\*.obj
if exist %BIN_DIR%\*.exe del /Q %BIN_DIR%\*.exe
if exist %BIN_DIR%\*.dll del /Q %BIN_DIR%\*.dll
if exist %BIN_DIR%\*.lib del /Q %BIN_DIR%\*.lib

:: Compile ASM kernels
echo.
echo [1/6] Compiling ASM kernels...
echo.

echo   - NanoMatMul_LUT2.asm
"%ML64%" /c /W3 /nologo /Zi /Fo"%OBJ_DIR%\NanoMatMul_LUT2.obj" "%SRC_DIR%\NanoMatMul_LUT2.asm" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to compile NanoMatMul_LUT2.asm
    goto :error
)

echo   - NanoMatMul_XNOR.asm
"%ML64%" /c /W3 /nologo /Zi /Fo"%OBJ_DIR%\NanoMatMul_XNOR.obj" "%SRC_DIR%\NanoMatMul_XNOR.asm" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to compile NanoMatMul_XNOR.asm
    goto :error
)

echo   - Q4_Dequantize.asm
"%ML64%" /c /W3 /nologo /Zi /Fo"%OBJ_DIR%\Q4_Dequantize.obj" "%SRC_DIR%\Q4_Dequantize.asm" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to compile Q4_Dequantize.asm
    goto :error
)

echo   - Q8_Dequantize.asm
"%ML64%" /c /W3 /nologo /Zi /Fo"%OBJ_DIR%\Q8_Dequantize.obj" "%SRC_DIR%\Q8_Dequantize.asm" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to compile Q8_Dequantize.asm
    goto :error
)

:: Compile C++ sources
echo.
echo [2/6] Compiling C++ sources...
echo.

set CL_FLAGS=/c /W4 /EHsc /O2 /arch:AVX512 /Zi /nologo /I"%INC_DIR%" /D_CRT_SECURE_NO_WARNINGS /std:c++17

echo   - nevm_v2.cpp
"%CL%" %CL_FLAGS% /Fo"%OBJ_DIR%\nevm_v2.obj" "%SRC_DIR%\nevm_v2.cpp" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to compile nevm_v2.cpp
    goto :error
)

echo   - nevm_mmu.cpp
"%CL%" %CL_FLAGS% /Fo"%OBJ_DIR%\nevm_mmu.obj" "%SRC_DIR%\nevm_mmu.cpp" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to compile nevm_mmu.cpp
    goto :error
)

echo   - nevm_residency.cpp
"%CL%" %CL_FLAGS% /Fo"%OBJ_DIR%\nevm_residency.obj" "%SRC_DIR%\nevm_residency.cpp" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to compile nevm_residency.cpp
    goto :error
)

echo   - nevm_precision_controller.cpp
"%CL%" %CL_FLAGS% /Fo"%OBJ_DIR%\nevm_precision_controller.obj" "%SRC_DIR%\nevm_precision_controller.cpp" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to compile nevm_precision_controller.cpp
    goto :error
)

echo   - nevm_prefetch.cpp
"%CL%" %CL_FLAGS% /Fo"%OBJ_DIR%\nevm_prefetch.obj" "%SRC_DIR%\nevm_prefetch.cpp" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to compile nevm_prefetch.cpp
    goto :error
)

echo   - nevm_trace.cpp
"%CL%" %CL_FLAGS% /Fo"%OBJ_DIR%\nevm_trace.obj" "%SRC_DIR%\nevm_trace.cpp" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to compile nevm_trace.cpp
    goto :error
)

echo   - nevm_transformer_engine.cpp
"%CL%" %CL_FLAGS% /Fo"%OBJ_DIR%\nevm_transformer_engine.obj" "%SRC_DIR%\nevm_transformer_engine.cpp" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to compile nevm_transformer_engine.cpp
    goto :error
)

echo   - nevm_benchmark.cpp
"%CL%" %CL_FLAGS% /Fo"%OBJ_DIR%\nevm_benchmark.obj" "%SRC_DIR%\nevm_benchmark.cpp" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to compile nevm_benchmark.cpp
    goto :error
)

:: Link DLL
echo.
echo [3/6] Linking N-EVM DLL...
echo.

set LINK_FLAGS=/DLL /SUBSYSTEM:WINDOWS /DEBUG /OPT:REF /OPT:ICF /LARGEADDRESSAWARE /NODEFAULTLIB:libcmt.lib
set LIBS=kernel32.lib user32.lib

"%LINK%" %LINK_FLAGS% %LIBS% ^
    /OUT:"%BIN_DIR%\RawrXD_NEVM.dll" ^
    /IMPLIB:"%BIN_DIR%\RawrXD_NEVM.lib" ^
    %OBJ_DIR%\nevm_v2.obj ^
    %OBJ_DIR%\nevm_mmu.obj ^
    %OBJ_DIR%\nevm_residency.obj ^
    %OBJ_DIR%\nevm_precision_controller.obj ^
    %OBJ_DIR%\nevm_prefetch.obj ^
    %OBJ_DIR%\nevm_trace.obj ^
    %OBJ_DIR%\nevm_transformer_engine.obj ^
    %OBJ_DIR%\nevm_benchmark.obj ^
    %OBJ_DIR%\NanoMatMul_LUT2.obj ^
    %OBJ_DIR%\NanoMatMul_XNOR.obj ^
    %OBJ_DIR%\Q4_Dequantize.obj ^
    %OBJ_DIR%\Q8_Dequantize.obj ^
    2>&1

if errorlevel 1 (
    echo ERROR: Failed to link DLL
    goto :error
)

:: Build test executable
echo.
echo [4/6] Building test executable...
echo.

:: Create test source
echo #include ^<cstdio^> > "%SRC_DIR%\test_nevm.cpp"
echo #include "nevm_v2.hpp" >> "%SRC_DIR%\test_nevm.cpp"
echo using namespace RawrXD::NEVM; >> "%SRC_DIR%\test_nevm.cpp"
echo int main() { >> "%SRC_DIR%\test_nevm.cpp"
echo     printf("RawrXD N-EVM v0.2 Test Harness\n"); >> "%SRC_DIR%\test_nevm.cpp"
echo     printf("==============================\n\n"); >> "%SRC_DIR%\test_nevm.cpp"
echo     NEVM_v2::Config config; >> "%SRC_DIR%\test_nevm.cpp"
echo     config.ram_budget = 64ULL*1024*1024*1024; >> "%SRC_DIR%\test_nevm.cpp"
echo     config.vram_budget = 16ULL*1024*1024*1024; >> "%SRC_DIR%\test_nevm.cpp"
echo     NEVM_v2* vm = new NEVM_v2(config); >> "%SRC_DIR%\test_nevm.cpp"
echo     if (!vm->Initialize()) { printf("FAIL: Could not initialize VM\n"); return 1; } >> "%SRC_DIR%\test_nevm.cpp"
echo     printf("[PASS] VM initialized successfully\n"); >> "%SRC_DIR%\test_nevm.cpp"
echo     printf("  RAM budget: 64GB\n"); >> "%SRC_DIR%\test_nevm.cpp"
echo     printf("  VRAM budget: 16GB\n"); >> "%SRC_DIR%\test_nevm.cpp"
echo     printf("  Version: %%s\n\n", NEVM_v2::GetVersion()); >> "%SRC_DIR%\test_nevm.cpp"
echo     delete vm; >> "%SRC_DIR%\test_nevm.cpp"
echo     printf("[PASS] VM destroyed successfully\n"); >> "%SRC_DIR%\test_nevm.cpp"
echo     printf("\nAll tests passed!\n"); >> "%SRC_DIR%\test_nevm.cpp"
echo     return 0; >> "%SRC_DIR%\test_nevm.cpp"
echo } >> "%SRC_DIR%\test_nevm.cpp"

"%CL%" /EHsc /O2 /Zi /nologo /I"%INC_DIR%" /Fe"%BIN_DIR%\test_nevm.exe" "%SRC_DIR%\test_nevm.cpp" /link "%BIN_DIR%\RawrXD_NEVM.lib" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to build test executable
    goto :error
)

:: Build comprehensive test harness
echo.
echo [4.5/6] Building comprehensive test harness...
echo.
"%CL%" /EHsc /O2 /Zi /nologo /I"%INC_DIR%" /Fe"%BIN_DIR%\nevm_test_harness.exe" "%SRC_DIR%\nevm_test_harness.cpp" /link "%BIN_DIR%\RawrXD_NEVM.lib" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to build comprehensive test harness
    goto :error
)

:: Build kernel validation
echo.
echo [4.6/6] Building kernel validation...
echo.
"%CL%" /EHsc /O2 /Zi /nologo /I"%INC_DIR%" /Fe"%BIN_DIR%\nevm_kernel_validation.exe" "%SRC_DIR%\nevm_kernel_validation.cpp" /link "%BIN_DIR%\RawrXD_NEVM.lib" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to build kernel validation
    goto :error
)

:: Build transformer validation
echo.
echo [4.7/6] Building transformer validation...
echo.
"%CL%" /EHsc /O2 /Zi /nologo /I"%INC_DIR%" /Fe"%BIN_DIR%\nevm_transformer_validation.exe" "%SRC_DIR%\nevm_transformer_validation.cpp" /link "%BIN_DIR%\RawrXD_NEVM.lib" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to build transformer validation
    goto :error
)

:: Build benchmark runner
echo.
echo [4.8/6] Building benchmark runner...
echo.
"%CL%" /EHsc /O2 /Zi /nologo /I"%INC_DIR%" /Fe"%BIN_DIR%\nevm_benchmark_runner.exe" "%SRC_DIR%\nevm_benchmark_runner.cpp" /link "%BIN_DIR%\RawrXD_NEVM.lib" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to build benchmark runner
    goto :error
)

:: Build logit validation
echo.
echo [4.9/6] Building logit validation...
echo.
"%CL%" /EHsc /O2 /Zi /nologo /I"%INC_DIR%" /Fe"%BIN_DIR%\nevm_logit_validation.exe" "%SRC_DIR%\nevm_logit_validation.cpp" /link "%BIN_DIR%\RawrXD_NEVM.lib" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to build logit validation
    goto :error
)

:: Build subsystem profiler
echo.
echo [4.10/6] Building subsystem profiler...
echo.
"%CL%" /EHsc /O2 /Zi /nologo /I"%INC_DIR%" /Fe"%BIN_DIR%\nevm_subsystem_profiler.exe" "%SRC_DIR%\nevm_subsystem_profiler.cpp" /link "%BIN_DIR%\RawrXD_NEVM.lib" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to build subsystem profiler
    goto :error
)

:: Build A/B testing
echo.
echo [4.11/6] Building A/B testing framework...
echo.
"%CL%" /EHsc /O2 /Zi /nologo /I"%INC_DIR%" /Fe"%BIN_DIR%\nevm_ab_testing.exe" "%SRC_DIR%\nevm_ab_testing.cpp" /link "%BIN_DIR%\RawrXD_NEVM.lib" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to build A/B testing
    goto :error
)

:: Build toggle utility
echo.
echo [4.12/6] Building toggle utility...
echo.
"%CL%" /EHsc /O2 /Zi /nologo /I"%INC_DIR%" /Fe"%BIN_DIR%\nevm_toggle.exe" "%SRC_DIR%\nevm_toggle.cpp" /link "%BIN_DIR%\RawrXD_NEVM.lib" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to build toggle utility
    goto :error
)

:: Build determinism validation
echo.
echo [4.13/6] Building determinism validation...
echo.
"%CL%" /EHsc /O2 /Zi /nologo /I"%INC_DIR%" /Fe"%BIN_DIR%\nevm_determinism_validation.exe" "%SRC_DIR%\nevm_determinism_validation.cpp" /link "%BIN_DIR%\RawrXD_NEVM.lib" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to build determinism validation
    goto :error
)

:: Build stress test
echo.
echo [4.14/6] Building stress test...
echo.
"%CL%" /EHsc /O2 /Zi /nologo /I"%INC_DIR%" /Fe"%BIN_DIR%\nevm_stress_test.exe" "%SRC_DIR%\nevm_stress_test.cpp" /link "%BIN_DIR%\RawrXD_NEVM.lib" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to build stress test
    goto :error
)

:: Build performance budget analyzer
echo.
echo [4.15/6] Building performance budget analyzer...
echo.
"%CL%" /EHsc /O2 /Zi /nologo /I"%INC_DIR%" /Fe"%BIN_DIR%\nevm_performance_budget.exe" "%SRC_DIR%\nevm_performance_budget.cpp" /link "%BIN_DIR%\RawrXD_NEVM.lib" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to build performance budget analyzer
    goto :error
)

:: Build extended stress test
echo.
echo [4.16/6] Building extended stress test...
echo.
"%CL%" /EHsc /O2 /Zi /nologo /I"%INC_DIR%" /Fe"%BIN_DIR%\nevm_extended_stress_test.exe" "%SRC_DIR%\nevm_extended_stress_test.cpp" /link "%BIN_DIR%\RawrXD_NEVM.lib" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to build extended stress test
    goto :error
)

:: Build unified validator
echo.
echo [4.17/6] Building unified validator...
echo.
"%CL%" /EHsc /O2 /Zi /nologo /I"%INC_DIR%" /Fe"%BIN_DIR%\nevm_validate.exe" "%SRC_DIR%\nevm_validate.cpp" /link "%BIN_DIR%\RawrXD_NEVM.lib" 2>&1
if errorlevel 1 (
    echo ERROR: Failed to build unified validator
    goto :error
)

:: Run tests
echo.
echo [5/6] Running tests...
echo.
"%BIN_DIR%\test_nevm.exe"
if errorlevel 1 (
    echo ERROR: Tests failed
    goto :error
)

:: Run comprehensive test harness
echo.
echo [5.5/6] Running comprehensive test harness...
echo.
"%BIN_DIR%\nevm_test_harness.exe"
if errorlevel 1 (
    echo ERROR: Comprehensive tests failed
    goto :error
)

:: Summary
echo.
echo [6/6] Build Summary
echo ============================================
echo.
echo Output files:
echo   DLL: %BIN_DIR%\RawrXD_NEVM.dll
echo   LIB: %BIN_DIR%\RawrXD_NEVM.lib
echo   PDB: %BIN_DIR%\RawrXD_NEVM.pdb
echo   Test: %BIN_DIR%\test_nevm.exe
echo   Test Harness: %BIN_DIR%\nevm_test_harness.exe
echo.
echo Object files:
dir /b "%OBJ_DIR%\*.obj" 2>nul | find /c ".obj"
echo.
echo ============================================
echo BUILD SUCCESSFUL
echo ============================================

goto :end

:error
echo.
echo ============================================
echo BUILD FAILED
echo ============================================
exit /b 1

:end
endlocal
