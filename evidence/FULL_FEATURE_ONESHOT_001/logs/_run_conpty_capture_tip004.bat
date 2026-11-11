@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001"
if not exist bin mkdir bin
cl /nologo /EHsc /O2 /I F:\rawrxd\src\win32app /Fe:bin\terminal_conpty_capture_tip004.exe harness\terminal_conpty_capture.cpp F:\rawrxd\src\win32app\Win32TerminalManager.cpp /link /nologo > logs\conpty_tip004_build.log 2>&1
if errorlevel 1 exit /b 1
bin\terminal_conpty_capture_tip004.exe > logs\conpty_capture_tip004_stdout.txt 2>&1
exit /b %ERRORLEVEL%
