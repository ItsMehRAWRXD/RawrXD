@echo off
REM RAWRXD Compiler Driver Uninstaller

echo ==========================================
echo RAWRXD Compiler Driver Uninstaller
echo ==========================================
echo.

set "INSTALL_DIR=%ProgramFiles%\RAWRXD"
set "USER_DIR=%USERPROFILE%\RAWRXD"

REM Check if installed
if not exist "%INSTALL_DIR%" (
    if not exist "%USER_DIR%" (
        echo RAWRXD Compiler Driver not found.
        echo It may have been already uninstalled.
        pause
        exit /b 0
    )
    set "INSTALL_DIR=%USER_DIR%"
)

echo Found installation at: %INSTALL_DIR%
echo.
echo This will remove:
echo   - %INSTALL_DIR%
echo   - PATH entry
echo.
choice /C YN /N /M "Are you sure you want to uninstall? (Y/N)"
if errorlevel 2 exit /b 0
if errorlevel 1 goto do_uninstall

:do_uninstall
echo.
echo Uninstalling...

REM Remove from PATH (this is tricky in batch, just warn)
echo [INFO] Please manually remove %INSTALL_DIR%\bin from your PATH
echo          if you added it manually.

REM Remove directory
if exist "%INSTALL_DIR%" (
    rmdir /S /Q "%INSTALL_DIR%"
    echo [OK] Removed installation directory
)

echo.
echo ==========================================
echo Uninstallation Complete!
echo ==========================================
echo.
echo RAWRXD Compiler Driver has been removed.
echo.
echo Note: If you added the bin directory to your PATH,
echo       please remove it manually from System Properties.
echo.
pause
