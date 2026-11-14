@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d "%~dp0"
if exist SetupWizard.exe.copybak del /f SetupWizard.exe.copybak
if exist SetupWizard.exe copy /y SetupWizard.exe SetupWizard.exe.copybak >nul
cl /nologo /O2 /W3 /EHsc /Fe:SetupWizard.exe SetupWizard.cpp SetupWizard_Offline_Fs.cpp /link shell32.lib ole32.lib
if errorlevel 1 exit /b 1
dir SetupWizard.exe
endlocal
exit /b 0
