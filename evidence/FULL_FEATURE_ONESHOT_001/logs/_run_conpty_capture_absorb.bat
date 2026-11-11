@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001"
cl /nologo /EHsc /O2 /I F:\rawrxd\src\win32app /Fe:bin\terminal_conpty_capture.exe harness\terminal_conpty_capture.cpp F:\rawrxd\src\win32app\Win32TerminalManager.cpp /link /nologo
if errorlevel 1 exit /b 1
bin\terminal_conpty_capture.exe
exit /b %ERRORLEVEL%
