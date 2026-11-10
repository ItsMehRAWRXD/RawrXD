@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001"
cl /nologo /EHsc /std:c++17 /O2 /I "F:\rawrxd\src\win32app" /Fe:harness\terminal_conpty_capture.exe harness\terminal_conpty_capture.cpp src\win32app\Win32TerminalManager.cpp /link user32.lib advapi32.lib
if errorlevel 1 exit /b 1
harness\terminal_conpty_capture.exe
