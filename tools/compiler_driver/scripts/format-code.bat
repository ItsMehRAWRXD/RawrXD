@echo off
:: RAWRXD Compiler Driver - Code Formatting Script
:: Formats all source files

echo ==========================================
echo RAWRXD Compiler Driver - Code Format
echo ==========================================
echo.

:: Check for clang-format
echo [INFO] Checking for clang-format...
where clang-format >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] clang-format not found!
    echo Please install LLVM/Clang tools
    pause
    exit /b 1
)

echo [OK] clang-format found

:: Format C source files
echo [INFO] Formatting C source files...
for /r "src" %%f in (*.c) do (
    echo   Formatting: %%f
    clang-format -i "%%f"
)

:: Format header files
echo [INFO] Formatting header files...
for /r "include" %%f in (*.h) do (
    echo   Formatting: %%f
    clang-format -i "%%f"
)

echo.
echo ==========================================
echo Formatting Complete!
echo ==========================================
echo.

pause
