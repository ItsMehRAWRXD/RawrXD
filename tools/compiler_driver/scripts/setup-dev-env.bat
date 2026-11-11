@echo off
REM RAWRXD Compiler Driver Development Environment Setup
REM Configures the development environment

echo ==========================================
echo RAWRXD Compiler Driver - Dev Environment Setup
echo ==========================================
echo.

set "PROJECT_ROOT=%~dp0.."
set "TOOLS_DIR=%PROJECT_ROOT%\tools"

REM Check for Visual Studio
echo Checking for Visual Studio...
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property installationPath`) do (
        set "VS_PATH=%%i"
    )
)

if defined VS_PATH (
    echo [OK] Found Visual Studio at: %VS_PATH%
) else (
    echo [WARNING] Visual Studio not found. Please install VS 2019 or later.
)

REM Create directory structure
echo.
echo Creating directory structure...
if not exist "%PROJECT_ROOT%\bin" mkdir "%PROJECT_ROOT%\bin"
if not exist "%PROJECT_ROOT%\obj" mkdir "%PROJECT_ROOT%\obj"
if not exist "%PROJECT_ROOT%\obj\backends" mkdir "%PROJECT_ROOT%\obj\backends"
if not exist "%PROJECT_ROOT%\releases" mkdir "%PROJECT_ROOT%\releases"
if not exist "%PROJECT_ROOT%\logs" mkdir "%PROJECT_ROOT%\logs"
echo [OK] Directories created

REM Check for required tools
echo.
echo Checking for required tools...

where git > nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [OK] Git found
) else (
    echo [WARNING] Git not found
)

where node > nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [OK] Node.js found
) else (
    echo [INFO] Node.js not found (needed for VS Code extension)
)

REM Create user config directory
set "CONFIG_DIR=%USERPROFILE%\.rawrxd"
if not exist "%CONFIG_DIR%" mkdir "%CONFIG_DIR%"

REM Create default config
echo.
echo Creating default configuration...
(
echo {
echo   "compiler": "rawrxd",
echo   "version": "1.0.0",
echo   "default_language": "auto",
echo   "optimize": false,
echo   "debug": true,
echo   "verbose": false,
echo   "backends": {
echo     "c": {
echo       "enabled": true,
echo       "path": ""
echo     },
echo     "asm": {
echo       "enabled": true,
echo       "path": ""
echo     },
echo     "csharp": {
echo       "enabled": true,
echo       "path": ""
echo     }
echo   }
echo }
) > "%CONFIG_DIR%\config.json"
echo [OK] Created %CONFIG_DIR%\config.json

REM Create PowerShell profile helper
echo.
echo Creating PowerShell profile helper...
(
echo # RAWRXD Compiler Driver PowerShell Module
echo function rawrxd { ^& "$env:USERPROFILE\.rawrxd\bin\rawrxd-compiler.exe" @args }
echo function rxc { rawrxd compile $args }
echo function rxbuild { rawrxd build $args }
echo function rxtest { ^& "$PSScriptRoot\..\tests\smoke_test.bat" }
echo Export-ModuleMember -Function rawrxd, rxc, rxbuild, rxtest
) > "%CONFIG_DIR%\RAWRXD.psm1"
echo [OK] Created PowerShell module

REM Create batch shortcuts
echo.
echo Creating command shortcuts...
(
echo @echo off
echo "%~dp0..\bin\rawrxd-compiler.exe" %%*
) > "%CONFIG_DIR%\rawrxd.bat"
echo [OK] Created rawrxd.bat

REM Add to PATH (user)
echo.
echo Adding to PATH...
setx PATH "%PATH%;%CONFIG_DIR%" > nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [OK] Added %CONFIG_DIR% to PATH
    echo [INFO] Restart your terminal for changes to take effect
) else (
    echo [WARNING] Could not update PATH automatically
    echo          Please add %CONFIG_DIR% to your PATH manually
)

REM Create VS Code settings
echo.
echo Creating VS Code settings...
if not exist "%PROJECT_ROOT%\.vscode" mkdir "%PROJECT_ROOT%\.vscode"
(
echo {
echo   "version": "0.2.0",
echo   "configurations": [
echo     {
echo       "name": "Debug Compiler",
echo       "type": "cppvsdbg",
echo       "request": "launch",
echo       "program": "${workspaceFolder}/bin/rawrxd-compiler.exe",
echo       "args": ["compile", "examples/hello_world/hello.c"],
echo       "stopAtEntry": false,
echo       "cwd": "${workspaceFolder}",
echo       "environment": [],
echo       "console": "integratedTerminal"
echo     }
echo   ],
echo   "tasks": [
echo     {
echo       "label": "Build",
echo       "type": "shell",
echo       "command": "build.bat",
echo       "group": {
echo         "kind": "build",
echo         "isDefault": true
echo       }
echo     },
echo     {
echo       "label": "Test",
echo       "type": "shell",
echo       "command": "tests/smoke_test.bat",
echo       "group": "test"
echo     }
echo   ]
echo }
) > "%PROJECT_ROOT%\.vscode\launch.json"
echo [OK] Created VS Code launch configuration

REM Create git hooks (if git repo)
if exist "%PROJECT_ROOT%\.git" (
    echo.
    echo Setting up git hooks...
    (
        echo @echo off
echo echo Running pre-commit checks...
echo call tests\smoke_test.bat
echo if errorlevel 1 (
echo     echo Tests failed. Commit aborted.
echo     exit /b 1
echo ^)
echo exit /b 0
    ) > "%PROJECT_ROOT%\.git\hooks\pre-commit.bat"
    echo [OK] Created pre-commit hook
)

echo.
echo ==========================================
echo Development Environment Setup Complete!
echo ==========================================
echo.
echo Next steps:
echo   1. Build the project: build.bat
echo   2. Run tests: tests\smoke_test.bat
echo   3. Try examples: rawrxd compile examples\hello_world\hello.c
echo.
echo Configuration: %CONFIG_DIR%\config.json
echo.
pause
