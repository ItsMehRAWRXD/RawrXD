@echo off
REM RAWRXD Compiler Driver Release Packager
REM Creates a distributable release package

setlocal enabledelayedexpansion

set "VERSION=1.0.0"
set "RELEASE_NAME=rawrxd-compiler-v%VERSION%"
set "RELEASE_DIR=%~dp0..\..\releases"
set "BUILD_DIR=%~dp0..\bin"
set "SOURCE_DIR=%~dp0.."

set "TEMP_DIR=%TEMP%\%RELEASE_NAME%"

echo ==========================================
echo RAWRXD Compiler Driver Release Packager
echo Version: %VERSION%
echo ==========================================
echo.

REM Check if binary exists
if not exist "%BUILD_DIR%\rawrxd-compiler.exe" (
    echo ERROR: Compiler not built yet!
    echo Please run build.bat first.
    exit /b 1
)

REM Create release directory
if not exist "%RELEASE_DIR%" mkdir "%RELEASE_DIR%"

REM Clean temp directory
if exist "%TEMP_DIR%" rmdir /S /Q "%TEMP_DIR%"
mkdir "%TEMP_DIR%"

echo Creating release package...

REM Copy executable
copy "%BUILD_DIR%\rawrxd-compiler.exe" "%TEMP_DIR%\" > nul
echo [OK] Executable

REM Copy documentation
copy "%SOURCE_DIR%\README.md" "%TEMP_DIR%\" > nul
copy "%SOURCE_DIR%\RAWRXD_COMPILER_QUICK_REFERENCE.md" "%TEMP_DIR%\" > nul
echo [OK] Documentation

REM Copy examples
xcopy /E /I "%SOURCE_DIR%\examples" "%TEMP_DIR%\examples" > nul
echo [OK] Examples

REM Copy tools
xcopy /E /I "%SOURCE_DIR%\tools" "%TEMP_DIR%\tools" > nul
echo [OK] Tools

REM Copy tests
xcopy /E /I "%SOURCE_DIR%\tests" "%TEMP_DIR%\tests" > nul
echo [OK] Tests

REM Create license file
(
echo MIT License
echo.
echo Copyright ^(c^) 2026 RAWRXD Project
echo.
echo Permission is hereby granted, free of charge, to any person obtaining a copy
echo of this software and associated documentation files ^(the "Software"^), to deal
echo in the Software without restriction, including without limitation the rights
echo to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
echo copies of the Software, and to permit persons to whom the Software is
echo furnished to do so, subject to the following conditions:
echo.
echo The above copyright notice and this permission notice shall be included in all
echo copies or substantial portions of the Software.
echo.
echo THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
echo IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
echo FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
echo AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
echo LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
echo OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
echo SOFTWARE.
) > "%TEMP_DIR%\LICENSE.txt"
echo [OK] License

REM Create install script
(
echo @echo off
echo REM RAWRXD Compiler Driver Installer
echo.
echo echo Installing RAWRXD Compiler Driver...
echo.
echo REM Copy to Program Files
echo if not exist "%%ProgramFiles%%\RAWRXD" mkdir "%%ProgramFiles%%\RAWRXD"
echo copy /Y "rawrxd-compiler.exe" "%%ProgramFiles%%\RAWRXD\" ^> nul
echo.
echo REM Add to PATH
echo setx PATH "%%PATH%%;%%ProgramFiles%%\RAWRXD" /M ^> nul
echo.
echo echo Installation complete!
echo echo.
echo echo You may need to restart your command prompt for PATH changes to take effect.
echo pause
) > "%TEMP_DIR%\install.bat"
echo [OK] Installer

REM Create uninstall script
(
echo @echo off
echo REM RAWRXD Compiler Driver Uninstaller
echo.
echo echo Uninstalling RAWRXD Compiler Driver...
echo.
echo REM Remove from Program Files
echo if exist "%%ProgramFiles%%\RAWRXD\rawrxd-compiler.exe" (
echo     del /F /Q "%%ProgramFiles%%\RAWRXD\rawrxd-compiler.exe"
echo     rmdir "%%ProgramFiles%%\RAWRXD" 2^>nul
echo     echo [OK] Removed executable
echo ^)
echo.
echo echo Uninstallation complete!
echo pause
) > "%TEMP_DIR%\uninstall.bat"
echo [OK] Uninstaller

REM Create ZIP file
echo.
echo Creating ZIP archive...
cd /d "%TEMP%"
powershell -Command "Compress-Archive -Path '%RELEASE_NAME%' -DestinationPath '%RELEASE_DIR%\%RELEASE_NAME%.zip' -Force"
if errorlevel 1 (
    echo ERROR: Failed to create ZIP
    exit /b 1
)

echo [OK] Created %RELEASE_NAME%.zip

REM Create installer EXE (optional - requires external tool)
REM echo Creating installer EXE...
REM This would require NSIS or similar tool

echo.
echo ==========================================
echo Release Package Created Successfully!
echo ==========================================
echo.
echo Location: %RELEASE_DIR%\%RELEASE_NAME%.zip
echo.
echo Contents:
echo   - rawrxd-compiler.exe
echo   - README.md
echo   - LICENSE.txt
echo   - examples/
echo   - tools/
echo   - tests/
echo   - install.bat
echo   - uninstall.bat
echo.

REM Cleanup
rmdir /S /Q "%TEMP_DIR%"

endlocal
