@echo off
REM Build script for rawrxd_drive_audit

setlocal enabledelayedexpansion

set SRC_DIR=%~dp0
set BUILD_DIR=%SRC_DIR%\build

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo Building rawrxd_drive_audit...

REM Compile the audit module
cl /std:c11 /W3 /O2 /I "%SRC_DIR%" /c "%SRC_DIR%\rawrxd_drive_audit.c" /Fo"%BUILD_DIR%\rawrxd_drive_audit.obj" /nologo
if errorlevel 1 goto :error

REM Compile the example
echo Building example...
cl /std:c11 /W3 /O2 /I "%SRC_DIR%" /c "%SRC_DIR%\examples\drive_audit_example.c" /Fo"%BUILD_DIR%\drive_audit_example.obj" /nologo
if errorlevel 1 goto :error

REM Link
echo Linking...
link /OUT:"%BUILD_DIR%\drive_audit.exe" "%BUILD_DIR%\rawrxd_drive_audit.obj" "%BUILD_DIR%\drive_audit_example.obj" kernel32.lib /nologo
if errorlevel 1 goto :error

echo.
echo Build successful!
echo Executable: %BUILD_DIR%\drive_audit.exe
echo.
echo Usage: %BUILD_DIR%\drive_audit.exe [target_path] [output_json]
echo   Default target: D:\
echo   Default output: d_drive_audit.json
echo.

if "%1"=="run" (
    echo Running audit...
    "%BUILD_DIR%\drive_audit.exe"
)

goto :end

:error
echo Build failed!
exit /b 1

:end
endlocal
