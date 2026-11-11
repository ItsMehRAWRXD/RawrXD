@echo off
:: RAWRXD Compiler Driver - Quick Install Script
:: One-command installation for Windows

echo ==========================================
echo RAWRXD Compiler Driver - Quick Installer
echo ==========================================
echo.

:: Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running with administrator privileges
) else (
    echo [WARNING] Not running as administrator
    echo Some features may require admin rights.
    echo.
)

:: Check if already built
if not exist "bin\rawrxd-compiler.exe" (
    echo [INFO] Compiler not built yet. Building now...
    echo.
    call build.bat
    if errorlevel 1 (
        echo [ERROR] Build failed!
        pause
        exit /b 1
    )
    echo.
)

:: Run installer
echo [INFO] Running installer...
call install.bat

if errorlevel 1 (
    echo [ERROR] Installation failed!
    pause
    exit /b 1
)

echo.
echo ==========================================
echo Installation Complete!
echo ==========================================
echo.
echo You can now use: rawrxd-compiler
echo.
echo Try: rawrxd-compiler --help
echo.

pause
