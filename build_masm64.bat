@echo off
REM RawrXD Pure MASM64 Build - Quick Start
REM Usage: build_masm64.bat [debug|release] [clean] [verbose]

setlocal enabledelayedexpansion

echo ================================================================
echo   RawrXD Pure MASM64 Build
echo   Zero C++ Dependencies
echo ================================================================
echo.

REM Check for PowerShell
where pwsh >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "PSHELL=pwsh"
) else (
    where powershell >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        set "PSHELL=powershell"
    ) else (
        echo [ERROR] PowerShell not found
        exit /b 1
    )
)

REM Run the fixed build script
%PSHELL% -ExecutionPolicy Bypass -File "%~dp0build_pure_masm64_fixed.ps1" %*

exit /b %ERRORLEVEL%