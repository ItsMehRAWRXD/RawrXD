@echo off
REM RawrXD Portable Package Creator
REM Phase 8 - Task 18: Portable Distribution

setlocal EnableDelayedExpansion

set "VERSION=1.1.0"
set "BUILD_DIR=..\build\Release"
set "PACKAGE_DIR=RawrXD-%VERSION%-portable"
set "OUTPUT_FILE=RawrXD-%VERSION%-portable.zip"

echo ==========================================
echo RawrXD Portable Package Creator v%VERSION%
echo ==========================================
echo.

REM Create package directory structure
echo Creating package structure...
if exist "%PACKAGE_DIR%" rmdir /S /Q "%PACKAGE_DIR%"

mkdir "%PACKAGE_DIR%\bin"
mkdir "%PACKAGE_DIR%\models"
mkdir "%PACKAGE_DIR%\config"
mkdir "%PACKAGE_DIR%\cache"
mkdir "%PACKAGE_DIR%\logs"
mkdir "%PACKAGE_DIR%\docs"

REM Copy executables
echo Copying executables...
copy "%BUILD_DIR%\RawrXD_Gold.exe" "%PACKAGE_DIR%\bin\" >nul 2>&1
if errorlevel 1 echo Warning: RawrXD_Gold.exe not found

copy "%BUILD_DIR%\RawrXD-Win32IDE.exe" "%PACKAGE_DIR%\bin\" >nul 2>&1
if errorlevel 1 echo Warning: RawrXD-Win32IDE.exe not found

copy "%BUILD_DIR%\RawrEngine.exe" "%PACKAGE_DIR%\bin\" >nul 2>&1
if errorlevel 1 echo Warning: RawrEngine.exe not found

REM Copy DLLs
echo Copying dependencies...
for %%D in (vulkan-1.dll, msvcp140.dll, vcruntime140.dll, vcruntime140_1.dll) do (
    copy "%BUILD_DIR%\%%D" "%PACKAGE_DIR%\bin\" >nul 2>&1
)

REM Copy documentation
echo Copying documentation...
copy "..\README.md" "%PACKAGE_DIR%\docs\" >nul 2>&1
copy "..\LICENSE" "%PACKAGE_DIR%\docs\" >nul 2>&1
copy "..\CHANGELOG.md" "%PACKAGE_DIR%\docs\" >nul 2>&1

REM Create portable configuration
echo Creating portable configuration...
(
echo {
echo   "portable": true,
echo   "configPath": "config",
echo   "modelPath": "models",
echo   "cachePath": "cache",
echo   "logPath": "logs",
echo   "version": "%VERSION%"
echo }
) > "%PACKAGE_DIR%\config\portable.json"

REM Create launcher scripts
echo Creating launcher scripts...
(
echo @echo off
echo REM RawrXD Portable Launcher
echo.
echo set "RAWRXD_HOME=%%~dp0"
echo set "PATH=%%RAWXD_HOME%%\bin;%%PATH%%"
echo.
echo REM Set portable mode environment variable
echo set "RAWXD_PORTABLE=1"
echo set "RAWXD_CONFIG_PATH=%%RAWXD_HOME%%config"
echo set "RAWXD_MODEL_PATH=%%RAWXD_HOME%%models"
echo set "RAWXD_CACHE_PATH=%%RAWXD_HOME%%cache"
echo set "RAWXD_LOG_PATH=%%RAWXD_HOME%%logs"
echo.
echo echo Starting RawrXD in portable mode...
echo start "" "%%RAWXD_HOME%%bin\RawrXD-Win32IDE.exe" %%*
) > "%PACKAGE_DIR%\Start-RawrXD.bat"

(
echo @echo off
echo REM RawrXD CLI Portable Launcher
echo.
echo set "RAWXD_HOME=%%~dp0"
echo set "PATH=%%RAWXD_HOME%%\bin;%%PATH%%"
echo.
echo set "RAWXD_PORTABLE=1"
echo set "RAWXD_CONFIG_PATH=%%RAWXD_HOME%%config"
echo set "RAWXD_MODEL_PATH=%%RAWXD_HOME%%models"
echo.
echo "%%RAWXD_HOME%%bin\RawrEngine.exe" %%*
) > "%PACKAGE_DIR%\RawrXD-CLI.bat"

REM Create README for portable version
echo Creating portable README...
(
echo # RawrXD Portable v%VERSION%
echo.
echo ## Quick Start
echo.
echo 1. Double-click `Start-RawrXD.bat` to launch the IDE
echo 2. For command-line usage, run `RawrXD-CLI.bat --help`
echo 3. Place model files in the `models` folder
echo.
echo ## Folder Structure
echo.
echo - `bin/` - Executables and DLLs
echo - `models/` - Place your .gguf model files here
echo - `config/` - Configuration files
echo - `cache/` - Model cache and temporary files
echo - `logs/` - Application logs
echo - `docs/` - Documentation
echo.
echo ## USB Portable Mode
echo.
echo This package is designed to run from any location including USB drives.
echo All data is stored relative to the application folder.
echo.
echo ## System Requirements
echo.
echo - Windows 10/11 64-bit
echo - Vulkan-compatible GPU (optional, for GPU acceleration)
echo - 8GB RAM minimum (16GB+ recommended)
echo - 10GB free disk space
echo.
echo ## No Installation Required
echo.
echo RawrXD Portable does not require installation and makes no changes
echo to your system registry. Simply delete the folder to uninstall.
) > "%PACKAGE_DIR%\README-PORTABLE.txt"

REM Create ZIP archive
echo Creating ZIP archive...
if exist "%OUTPUT_FILE%" del "%OUTPUT_FILE%"

powershell -Command "Compress-Archive -Path '%PACKAGE_DIR%\*' -DestinationPath '%OUTPUT_FILE%' -Force"

if exist "%OUTPUT_FILE%" (
    echo.
    echo ==========================================
    echo Package created successfully!
    echo ==========================================
    echo Output: %OUTPUT_FILE%
    for %%I in ("%OUTPUT_FILE%") do echo Size: %%~zI bytes
    echo.
    echo To test: Extract %OUTPUT_FILE% and run Start-RawrXD.bat
) else (
    echo ERROR: Failed to create package
    exit /b 1
)

REM Cleanup
rmdir /S /Q "%PACKAGE_DIR%"

echo.
echo Done!
pause
