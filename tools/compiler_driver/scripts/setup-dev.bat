@echo off
:: RAWRXD Compiler Driver - Development Setup Script
:: Sets up the development environment

echo ==========================================
echo RAWRXD Compiler Driver - Dev Setup
echo ==========================================
echo.

:: Check for Visual Studio
echo [INFO] Checking for Visual Studio...
where cl >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Visual Studio C compiler found
) else (
    echo [WARNING] Visual Studio C compiler not found
    echo Please run this script from "x64 Native Tools Command Prompt"
)

:: Check for Git
echo [INFO] Checking for Git...
where git >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Git found
    git --version
) else (
    echo [WARNING] Git not found
)

:: Create directories
echo [INFO] Creating directories...
if not exist "obj" mkdir obj
if not exist "obj\backends" mkdir obj\backends
if not exist "bin" mkdir bin
if not exist "logs" mkdir logs
echo [OK] Directories created

:: Check for VS Code
echo [INFO] Checking for VS Code...
where code >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] VS Code found
    
    :: Install recommended extensions
    echo [INFO] Installing recommended extensions...
    code --install-extension ms-vscode.cpptools
    code --install-extension editorconfig.editorconfig
    echo [OK] Extensions installed
) else (
    echo [INFO] VS Code not found (optional)
)

echo.
echo ==========================================
echo Setup Complete!
echo ==========================================
echo.
echo Next steps:
echo   1. Run: build.bat
echo   2. Run: tests\smoke_test.bat
echo   3. Start coding!
echo.

pause
