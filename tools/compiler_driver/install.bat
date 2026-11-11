@echo off
REM RAWRXD Compiler Driver Installer
REM Zero-dependency installation

echo ==========================================
echo RAWRXD Compiler Driver Installer
echo Version 1.0.0
echo ==========================================
echo.

set "INSTALL_DIR=%ProgramFiles%\RAWRXD"
set "BIN_DIR=%INSTALL_DIR%\bin"
set "CURRENT_DIR=%~dp0"

REM Check for admin rights
net session > nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [WARNING] Administrator rights recommended for system-wide install.
    echo.
    echo Options:
    echo   1. Run as Administrator (recommended)
    echo   2. Install to user directory
    echo   3. Cancel
    echo.
    choice /C 123 /N /M "Select option:"
    if errorlevel 3 exit /b 0
    if errorlevel 2 goto user_install
    if errorlevel 1 goto admin_check
)

:admin_check
REM Check if binary exists
if not exist "%CURRENT_DIR%\bin\rawrxd-compiler.exe" (
    echo ERROR: rawrxd-compiler.exe not found!
    echo Please build first: build.bat
    pause
    exit /b 1
)

echo Installing to %INSTALL_DIR%...

REM Create directories
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

REM Copy executable
copy /Y "%CURRENT_DIR%\bin\rawrxd-compiler.exe" "%BIN_DIR%\" > nul
echo [OK] Installed executable

REM Copy documentation
copy /Y "%CURRENT_DIR%\README.md" "%INSTALL_DIR%\" > nul 2>&1
copy /Y "%CURRENT_DIR%\RAWRXD_COMPILER_QUICK_REFERENCE.md" "%INSTALL_DIR%\" > nul 2>&1
echo [OK] Installed documentation

REM Copy examples
if exist "%CURRENT_DIR%\examples" (
    xcopy /E /I /Y "%CURRENT_DIR%\examples" "%INSTALL_DIR%\examples\" > nul 2>&1
    echo [OK] Installed examples
)

REM Add to PATH
echo Adding to system PATH...
setx PATH "%PATH%;%BIN_DIR%" /M > nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [OK] Added to PATH
) else (
    echo [WARNING] Could not update PATH automatically
    echo          Please add %BIN_DIR% to PATH manually
)

goto install_complete

:user_install
set "INSTALL_DIR=%USERPROFILE%\RAWRXD"
set "BIN_DIR=%INSTALL_DIR%\bin"

echo Installing to user directory: %INSTALL_DIR%...

if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

copy /Y "%CURRENT_DIR%\bin\rawrxd-compiler.exe" "%BIN_DIR%\" > nul
echo [OK] Installed executable

echo Adding to user PATH...
setx PATH "%PATH%;%BIN_DIR%" > nul 2>&1
echo [OK] Added to PATH

:install_complete
echo.
echo ==========================================
echo Installation Complete!
echo ==========================================
echo.
echo Installation directory: %INSTALL_DIR%
echo Binary location: %BIN_DIR%\rawrxd-compiler.exe
echo.
echo Next steps:
echo   1. Restart your command prompt
echo   2. Run: rawrxd-compiler version
echo   3. Try: rawrxd-compiler compile examples\hello_world\hello.c
echo.
echo Documentation: %INSTALL_DIR%\README.md
echo.
pause
