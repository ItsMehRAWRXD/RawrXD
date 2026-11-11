@echo off
:: RAWRXD Compiler Driver - Linting Script
:: Runs static analysis on source code

echo ==========================================
echo RAWRXD Compiler Driver - Lint
echo ==========================================
echo.

:: Check for cppcheck
echo [INFO] Checking for cppcheck...
where cppcheck >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARNING] cppcheck not found
    echo Skipping static analysis
    goto :skip_cppcheck
)

echo [OK] cppcheck found
echo [INFO] Running static analysis...
cppcheck --enable=all --std=c11 -I include src\ 2> logs\lint.log

if %errorLevel% == 0 (
    echo [OK] No issues found
) else (
    echo [INFO] Check logs\lint.log for details
)

:skip_cppcheck

:: Check for compiler warnings
echo [INFO] Building with all warnings...
call build.bat clean >nul 2>&1
call build.bat > logs\build.log 2>&1

echo.
echo ==========================================
echo Lint Complete!
echo ==========================================
echo.
echo Check logs\lint.log and logs\build.log for details
echo.

pause
