@echo off
REM ═══════════════════════════════════════════════════════════════════════════════
REM Build script for RawrXD Tree Attention Benchmark Suite
REM VAL-032: Reproducible performance validation
REM ═══════════════════════════════════════════════════════════════════════════════

setlocal EnableDelayedExpansion

REM Tool paths
set ML64="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set CL="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
set LINK="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"

REM Source and output paths
set SRC_DIR=d:\RawrXD\src
set TEST_DIR=d:\RawrXD\tests
set OBJ_DIR=d:\RawrXD\build\obj
set BIN_DIR=d:\RawrXD\build\bin

REM Create directories
if not exist %OBJ_DIR% mkdir %OBJ_DIR%
if not exist %BIN_DIR% mkdir %BIN_DIR%

echo ═══════════════════════════════════════════════════════════════════════════════
echo Building RawrXD Tree Attention Benchmark Suite
echo ═══════════════════════════════════════════════════════════════════════════════
echo.

REM Assemble the AVX-512 kernel
echo [1/4] Assembling AVX-512 kernel...
%ML64% /c /W3 /nologo /Zi /Fo %OBJ_DIR%\RawrXD_TreeAttention_Kernel.obj %SRC_DIR%\kernels\RawrXD_TreeAttention_Kernel.asm
if errorlevel 1 (
    echo ERROR: Assembly failed
    exit /b 1
)
echo       Assembly successful

REM Compile C++ wrapper
echo.
echo [2/4] Compiling C++ wrapper...
%CL% /c /O2 /W4 /nologo /EHsc /arch:AVX512 /Fo %OBJ_DIR%\TreeAttention_AVX512_Wrapper.obj %SRC_DIR%\inference\TreeAttention_AVX512_Wrapper.cpp
if errorlevel 1 (
    echo ERROR: C++ compilation failed
    exit /b 1
)
echo       Compilation successful

REM Compile TreeAttention.cpp
echo.
echo [3/4] Compiling TreeAttention implementation...
%CL% /c /O2 /W4 /nologo /EHsc /arch:AVX512 /Fo %OBJ_DIR%\RawrXD_TreeAttention.obj %SRC_DIR%\inference\RawrXD_TreeAttention.cpp
if errorlevel 1 (
    echo ERROR: TreeAttention compilation failed
    exit /b 1
)
echo       Compilation successful

REM Compile benchmark
echo.
echo [4/4] Compiling benchmark harness...
%CL% /O2 /W4 /nologo /EHsc /arch:AVX512 /Fe %BIN_DIR%\benchmark_tree_attention.exe %TEST_DIR%\benchmark_tree_attention.cpp %OBJ_DIR%\RawrXD_TreeAttention_Kernel.obj %OBJ_DIR%\TreeAttention_AVX512_Wrapper.obj %OBJ_DIR%\RawrXD_TreeAttention.obj
if errorlevel 1 (
    echo ERROR: Benchmark compilation failed
    exit /b 1
)
echo       Benchmark executable created

echo.
echo ═══════════════════════════════════════════════════════════════════════════════
echo Build Complete
echo ═══════════════════════════════════════════════════════════════════════════════
echo.
echo Executable: %BIN_DIR%\benchmark_tree_attention.exe
echo.
echo To run benchmark:
echo   %BIN_DIR%\benchmark_tree_attention.exe --iterations 10000
echo.

endlocal
