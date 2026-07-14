@echo off
REM RawrXD Toolchain Build and Test Script
REM No dependencies - pure C toolchain

echo ==========================================
echo RawrXD Toolchain - Build and Test
echo ==========================================
echo.

REM Check for GCC
where gcc >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: GCC not found in PATH
    echo Please install MinGW or MSYS2
    exit /b 1
)

echo [Step 1] Building working_assembler...
gcc -O2 -Wall -o working_assembler.exe working_assembler.c
if %errorlevel% neq 0 (
    echo FAILED to build assembler
    exit /b 1
)
echo OK - working_assembler.exe built

echo.
echo [Step 2] Building working_linker...
gcc -O2 -Wall -o working_linker.exe working_linker.c
if %errorlevel% neq 0 (
    echo FAILED to build linker
    exit /b 1
)
echo OK - working_linker.exe built

echo.
echo [Step 3] Building minimal_gguf_loader...
gcc -O2 -Wall -o minimal_gguf_loader.exe minimal_gguf_loader.c
if %errorlevel% neq 0 (
    echo FAILED to build GGUF loader
    exit /b 1
)
echo OK - minimal_gguf_loader.exe built

echo.
echo [Step 4] Building test suite...
gcc -O2 -o toolchain_test_suite.exe toolchain_test_suite.c
if %errorlevel% neq 0 (
    echo FAILED to build test suite
    exit /b 1
)
echo OK - toolchain_test_suite.exe built

echo.
echo ==========================================
echo Running Test Suite...
echo ==========================================
toolchain_test_suite.exe

echo.
echo ==========================================
echo Build Complete!
echo ==========================================
echo.
echo Working components:
echo   - working_assembler.exe   (asm -^> obj)
echo   - working_linker.exe      (obj -^> exe)
echo   - minimal_gguf_loader.exe (GGUF parser)
echo   - toolchain_test_suite.exe (verification)
echo.
pause
