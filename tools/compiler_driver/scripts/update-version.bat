@echo off
REM RAWRXD Compiler Driver Version Updater
REM Updates version numbers across all files

setlocal enabledelayedexpansion

if "%~1"=="" (
    echo Usage: update-version.bat <new-version>
    echo Example: update-version.bat 1.1.0
    exit /b 1
)

set "NEW_VERSION=%~1"
set "OLD_VERSION=1.0.0"

echo ==========================================
echo Updating Version: %OLD_VERSION% -> %NEW_VERSION%
echo ==========================================
echo.

set "PROJECT_ROOT=%~dp0.."

REM Update header file
echo Updating header file...
powershell -Command "(Get-Content '%PROJECT_ROOT%\include\rawrxd_compiler.h') -replace 'RAWRXD_COMPILER_VERSION_MAJOR 1', 'RAWRXD_COMPILER_VERSION_MAJOR %NEW_VERSION:~0,1%' -replace 'RAWRXD_COMPILER_VERSION_MINOR 0', 'RAWRXD_COMPILER_VERSION_MINOR %NEW_VERSION:~2,1%' -replace 'RAWRXD_COMPILER_VERSION_PATCH 0', 'RAWRXD_COMPILER_VERSION_PATCH %NEW_VERSION:~4,1%' | Set-Content '%PROJECT_ROOT%\include\rawrxd_compiler.h'"
echo [OK] include\rawrxd_compiler.h

REM Update package.json
echo Updating package.json...
powershell -Command "(Get-Content '%PROJECT_ROOT%\vscode-extension\package.json') -replace '\"version\": \"1.0.0\"', '\"version\": \"%NEW_VERSION%\"' | Set-Content '%PROJECT_ROOT%\vscode-extension\package.json'"
echo [OK] vscode-extension\package.json

REM Update manifest
echo Updating manifest...
powershell -Command "(Get-Content '%PROJECT_ROOT%\compiler_manifest.json') -replace '\"version\": \"1.0.0\"', '\"version\": \"%NEW_VERSION%\"' | Set-Content '%PROJECT_ROOT%\compiler_manifest.json'"
echo [OK] compiler_manifest.json

REM Update documentation
echo Updating documentation...
for %%f in (%PROJECT_ROOT%\*.md) do (
    powershell -Command "(Get-Content '%%f') -replace '1\.0\.0', '%NEW_VERSION%' | Set-Content '%%f'" 2>nul
)
echo [OK] Documentation files

echo.
echo ==========================================
echo Version Update Complete!
echo ==========================================
echo.
echo New version: %NEW_VERSION%
echo Remember to rebuild the project.
echo.

endlocal
