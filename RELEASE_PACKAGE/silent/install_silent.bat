@echo off
REM RAWRXD silent install drop — copies bin + INSTALL.md to %ProgramFiles%\RawrXD
set DEST=%ProgramFiles%\RawrXD
mkdir "%DEST%" 2>nul
copy /Y "%~dp0..\INSTALL.md" "%DEST%\INSTALL.md" >nul
if exist "%~dp0..\..\build-fd\bin\rawr.exe" copy /Y "%~dp0..\..\build-fd\bin\rawr.exe" "%DEST%\rawr.exe" >nul
echo RAWRXD_INSTALLER_SILENT_EXE_001=RAN
exit /b 0
