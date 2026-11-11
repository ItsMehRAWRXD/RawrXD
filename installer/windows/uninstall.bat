@echo off
REM uninstall.bat
REM Phase H.3 Batch 1/5: Windows Uninstallation

setlocal EnableDelayedExpansion

set "LOG_FILE=%TEMP%\RawrXD_Uninstall.log"
set "INSTALL_DIR=%~1"

if "%INSTALL_DIR%"=="" (
    REM Try to get from registry
    for /f "tokens=2*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RawrXD" /v InstallLocation 2^>nul ^| findstr InstallLocation') do (
        set "INSTALL_DIR=%%b"
    )
)

if "%INSTALL_DIR%"=="" (
    echo ERROR: Installation directory not found
    exit /b 1
)

echo Starting RawrXD uninstallation... > "%LOG_FILE%"
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

REM Stop service if running
echo Stopping RawrXD service... >> "%LOG_FILE%"
sc stop RawrXD 2>nul
sc delete RawrXD 2>nul

REM Backup configuration before removal
echo Backing up configuration... >> "%LOG_FILE%"
if exist "%INSTALL_DIR%\config\rawrxd.yaml" (
    set "BACKUP_DIR=%USERPROFILE%\Documents\RawrXD_Backup"
    if not exist "!BACKUP_DIR!" mkdir "!BACKUP_DIR!"
    copy /Y "%INSTALL_DIR%\config\rawrxd.yaml" "!BACKUP_DIR!\rawrxd.yaml.backup" >nul
    echo Configuration backed up to: !BACKUP_DIR!\rawrxd.yaml.backup >> "%LOG_FILE%"
)

REM Remove files
echo Removing files... >> "%LOG_FILE%"
if exist "%INSTALL_DIR%" (
    rmdir /S /Q "%INSTALL_DIR%" 2>nul
    if exist "%INSTALL_DIR%" (
        echo WARNING: Could not remove all files >> "%LOG_FILE%"
        echo Some files may be in use. Please restart and try again.
    )
)

REM Remove from PATH
echo Updating PATH... >> "%LOG_FILE%"
for /f "tokens=2*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH 2^>nul ^| findstr PATH') do (
    set "CURRENT_PATH=%%b"
)
set "NEW_PATH=!CURRENT_PATH:%INSTALL_DIR%=!"
setx /M PATH "!NEW_PATH!" >nul 2>&1

REM Remove registry entries
echo Removing registry entries... >> "%LOG_FILE%"
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RawrXD" /f >nul 2>&1

echo. >> "%LOG_FILE%"
echo Uninstallation completed >> "%LOG_FILE%"
echo Timestamp: %date% %time% >> "%LOG_FILE%"

echo RawrXD uninstalled successfully
echo Configuration backed up to: %USERPROFILE%\Documents\RawrXD_Backup
exit /b 0
