@echo off
REM silent_install.bat
REM Phase H.3 Batch 1/5: Windows Silent Installation

setlocal EnableDelayedExpansion

set "VERSION=%~1"
if "%VERSION%"=="" set "VERSION=1.0.0"

set "INSTALL_DIR=%~2"
if "%INSTALL_DIR%"=="" set "INSTALL_DIR=%ProgramFiles%\RawrXD"

set "LOG_FILE=%TEMP%\RawrXD_Install_%VERSION%.log"

echo Starting RawrXD v%VERSION% silent installation... > "%LOG_FILE%"
echo Target: %INSTALL_DIR% >> "%LOG_FILE%"
echo Timestamp: %date% %time% >> "%LOG_FILE%"
echo. >> "%LOG_FILE%"

REM Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Administrator privileges required >> "%LOG_FILE%"
    echo Administrator privileges required. Please run as Administrator.
    exit /b 1
)

REM Check if already installed
if exist "%INSTALL_DIR%\RawrXD.exe" (
    echo Existing installation detected at %INSTALL_DIR% >> "%LOG_FILE%"
    
    REM Get current version
    for /f "tokens=*" %%a in ('"%INSTALL_DIR%\RawrXD.exe" --version 2^>nul') do (
        set "CURRENT_VERSION=%%a"
    )
    
    echo Current version: %CURRENT_VERSION% >> "%LOG_FILE%"
    echo Upgrading to: %VERSION% >> "%LOG_FILE%"
    
    REM Backup existing config
    if exist "%INSTALL_DIR%\config\rawrxd.yaml" (
        echo Backing up configuration... >> "%LOG_FILE%"
        copy /Y "%INSTALL_DIR%\config\rawrxd.yaml" "%TEMP%\rawrxd.yaml.backup" >nul
    )
)

REM Create directories
echo Creating directories... >> "%LOG_FILE%"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%INSTALL_DIR%\config" mkdir "%INSTALL_DIR%\config"
if not exist "%INSTALL_DIR%\logs" mkdir "%INSTALL_DIR%\logs"
if not exist "%INSTALL_DIR%\data" mkdir "%INSTALL_DIR%\data"

REM Copy files (placeholder - actual files would be extracted from MSI)
echo Installing files... >> "%LOG_FILE%"
echo Binary installation would occur here >> "%LOG_FILE%"

REM Restore config if backup exists
if exist "%TEMP%\rawrxd.yaml.backup" (
    echo Restoring configuration... >> "%LOG_FILE%"
    copy /Y "%TEMP%\rawrxd.yaml.backup" "%INSTALL_DIR%\config\rawrxd.yaml" >nul
    del "%TEMP%\rawrxd.yaml.backup"
)

REM Add to PATH
echo Updating PATH... >> "%LOG_FILE%"
setx /M PATH "%PATH%;%INSTALL_DIR%" >nul 2>&1

REM Create uninstaller registry entry
echo Creating registry entries... >> "%LOG_FILE%"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RawrXD" /v DisplayName /t REG_SZ /d "RawrXD Sovereign" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RawrXD" /v DisplayVersion /t REG_SZ /d "%VERSION%" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RawrXD" /v InstallLocation /t REG_SZ /d "%INSTALL_DIR%" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RawrXD" /v UninstallString /t REG_SZ /d "\"%INSTALL_DIR%\uninstall.exe\"" /f >nul

echo. >> "%LOG_FILE%"
echo Installation completed successfully >> "%LOG_FILE%"
echo Timestamp: %date% %time% >> "%LOG_FILE%"

echo RawrXD v%VERSION% installed successfully to %INSTALL_DIR%
echo Log: %LOG_FILE%
exit /b 0
