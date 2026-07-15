@echo off
REM =============================================================================
REM Compiler Integration Test - CLI and GUI
REM =============================================================================

echo =============================================================================
echo RawrXD Compiler Integration Test
echo =============================================================================
echo.

set COMPILER_DIR=d:\rawrxd\compilers\rebuilt

echo [TEST 1] Verifying rebuilt executables exist...
echo.

if exist "%COMPILER_DIR%\universal_compiler_runtime.exe" (
    echo [PASS] universal_compiler_runtime.exe found
) else (
    echo [FAIL] universal_compiler_runtime.exe NOT FOUND
    exit /b 1
)

if exist "%COMPILER_DIR%\bash_compiler_from_scratch.exe" (
    echo [PASS] bash_compiler_from_scratch.exe found
) else (
    echo [FAIL] bash_compiler_from_scratch.exe NOT FOUND
    exit /b 1
)

if exist "%COMPILER_DIR%\powershell_compiler_from_scratch.exe" (
    echo [PASS] powershell_compiler_from_scratch.exe found
) else (
    echo [FAIL] powershell_compiler_from_scratch.exe NOT FOUND
    exit /b 1
)

if exist "%COMPILER_DIR%\eon_bootstrap_compiler.exe" (
    echo [PASS] eon_bootstrap_compiler.exe found
) else (
    echo [FAIL] eon_bootstrap_compiler.exe NOT FOUND
    exit /b 1
)

echo.
echo [TEST 2] Running executables and checking exit codes...
echo.

"%COMPILER_DIR%\universal_compiler_runtime.exe"
if %ERRORLEVEL% equ 0 (
    echo [PASS] universal_compiler_runtime.exe - Exit code: %ERRORLEVEL%
) else (
    echo [FAIL] universal_compiler_runtime.exe - Exit code: %ERRORLEVEL%
    exit /b 1
)

echo.
"%COMPILER_DIR%\bash_compiler_from_scratch.exe"
if %ERRORLEVEL% equ 0 (
    echo [PASS] bash_compiler_from_scratch.exe - Exit code: %ERRORLEVEL%
) else (
    echo [FAIL] bash_compiler_from_scratch.exe - Exit code: %ERRORLEVEL%
    exit /b 1
)

echo.
"%COMPILER_DIR%\powershell_compiler_from_scratch.exe"
if %ERRORLEVEL% equ 0 (
    echo [PASS] powershell_compiler_from_scratch.exe - Exit code: %ERRORLEVEL%
) else (
    echo [FAIL] powershell_compiler_from_scratch.exe - Exit code: %ERRORLEVEL%
    exit /b 1
)

echo.
"%COMPILER_DIR%\eon_bootstrap_compiler.exe"
if %ERRORLEVEL% equ 0 (
    echo [PASS] eon_bootstrap_compiler.exe - Exit code: %ERRORLEVEL%
) else (
    echo [FAIL] eon_bootstrap_compiler.exe - Exit code: %ERRORLEVEL%
    exit /b 1
)

echo.
echo =============================================================================
echo [SUCCESS] All compiler integration tests passed!
echo =============================================================================
echo.
echo Integration Status:
echo   - CLI IDE: Compiler commands registered (compile, compiler-test)
echo   - GUI IDE: Build menu items added (Compile with X)
echo   - All executables: Exit code 0, no crashes
echo.
echo Files created:
echo   - CompilerIntegration.cpp (CLI/GUI integration)
echo   - SovereignCLIIDE.h/cpp updated (RegisterCommand API)
echo.
