@echo off
setlocal enabledelayedexpansion

echo ============================================
echo RawrXD GUI Installer Creator
echo ============================================

set "SOURCE_DIR=%~dp0.."
set "OUTPUT_DIR=%~dp0\output"
set "VERSION=14.7.3"

:: Create output directory
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo.
echo Creating RawrXD v%VERSION% Installer...
echo.

:: Create installer directory structure
set "INSTALLER_DIR=%OUTPUT_DIR%\RawrXD-%VERSION%"
mkdir "%INSTALLER_DIR%"
mkdir "%INSTALLER_DIR%\bin"
mkdir "%INSTALLER_DIR%\docs"
mkdir "%INSTALLER_DIR%\models"
mkdir "%INSTALLER_DIR%\config"

echo Copying files...

:: Copy executable
if exist "%SOURCE_DIR%\bin\RawrXD_GUI_Minimal.exe" (
    copy /Y "%SOURCE_DIR%\bin\RawrXD_GUI_Minimal.exe" "%INSTALLER_DIR%\bin\RawrXD.exe"
    echo [OK] RawrXD.exe
) else (
    echo [WARNING] RawrXD_GUI_Minimal.exe not found
)

:: Copy documentation
if exist "%SOURCE_DIR%\README_GUI.md" (
    copy /Y "%SOURCE_DIR%\README_GUI.md" "%INSTALLER_DIR%\docs\README.txt"
    echo [OK] README.txt
)

if exist "%SOURCE_DIR%\FINAL_STATUS.md" (
    copy /Y "%SOURCE_DIR%\FINAL_STATUS.md" "%INSTALLER_DIR%\docs\STATUS.txt"
    echo [OK] STATUS.txt
)

:: Create default config
echo Creating default configuration...
(
echo {
echo   "model_path": "",
echo   "theme": "dark",
echo   "font_size": 14,
echo   "auto_save": true,
echo   "streaming": true,
echo   "max_tokens": 2048
echo }
) > "%INSTALLER_DIR%\config\settings.json"
echo [OK] settings.json

:: Create start menu shortcut script
echo Creating installer script...
(
echo @echo off
echo echo Installing RawrXD v%VERSION%%%
echo echo.
echo set "INSTALL_DIR=%%LOCALAPPDATA%%\RawrXD"
echo set "START_MENU=%%APPDATA%%\Microsoft\Windows\Start Menu\Programs\RawrXD"
echo.
echo echo Creating directories...
echo if not exist "%%INSTALL_DIR%%" mkdir "%%INSTALL_DIR%%"
echo if not exist "%%START_MENU%%" mkdir "%%START_MENU%%"
echo.
echo echo Copying files...
echo xcopy /E /I /Y "%%~dp0bin" "%%INSTALL_DIR%%\bin"
echo xcopy /E /I /Y "%%~dp0docs" "%%INSTALL_DIR%%\docs"
echo xcopy /E /I /Y "%%~dp0config" "%%INSTALL_DIR%%\config"
echo xcopy /E /I /Y "%%~dp0models" "%%INSTALL_DIR%%\models"
echo.
echo echo Creating shortcuts...
echo powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%%START_MENU%%\RawrXD.lnk'); $Shortcut.TargetPath = '%%INSTALL_DIR%%\bin\RawrXD.exe'; $Shortcut.WorkingDirectory = '%%INSTALL_DIR%%\bin'; $Shortcut.Save()"
echo powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%%USERPROFILE%%\Desktop\RawrXD.lnk'); $Shortcut.TargetPath = '%%INSTALL_DIR%%\bin\RawrXD.exe'; $Shortcut.WorkingDirectory = '%%INSTALL_DIR%%\bin'; $Shortcut.Save()"
echo.
echo echo Installation complete!
echo echo RawrXD v%VERSION% has been installed to: %%INSTALL_DIR%%
echo echo.
echo pause
) > "%INSTALLER_DIR%\INSTALL.bat"

echo [OK] INSTALL.bat

:: Create uninstaller
echo Creating uninstaller...
(
echo @echo off
echo echo Uninstalling RawrXD v%VERSION%%%
echo echo.
echo set "INSTALL_DIR=%%LOCALAPPDATA%%\RawrXD"
echo set "START_MENU=%%APPDATA%%\Microsoft\Windows\Start Menu\Programs\RawrXD"
echo.
echo echo Removing files...
echo if exist "%%INSTALL_DIR%%" rmdir /S /Q "%%INSTALL_DIR%%"
echo if exist "%%START_MENU%%" rmdir /S /Q "%%START_MENU%%"
echo if exist "%%USERPROFILE%%\Desktop\RawrXD.lnk" del /Q "%%USERPROFILE%%\Desktop\RawrXD.lnk"
echo.
echo echo Uninstallation complete!
echo pause
) > "%INSTALLER_DIR%\UNINSTALL.bat"

echo [OK] UNINSTALL.bat

:: Create ZIP archive
echo.
echo Creating ZIP archive...
cd /d "%OUTPUT_DIR%"
powershell -Command "Compress-Archive -Path 'RawrXD-%VERSION%' -DestinationPath 'RawrXD-%VERSION%-Windows-x64.zip' -Force"

echo.
echo ============================================
echo Installer created successfully!
echo ============================================
echo.
echo Location: %OUTPUT_DIR%\RawrXD-%VERSION%-Windows-x64.zip
echo.
echo Contents:
echo   - RawrXD.exe (GUI Application)
echo   - Documentation
echo   - Default configuration
echo   - Install/Uninstall scripts
echo.
echo To install: Extract and run INSTALL.bat
echo.

endlocal
