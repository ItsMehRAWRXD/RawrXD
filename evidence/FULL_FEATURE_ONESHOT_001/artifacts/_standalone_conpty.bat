@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts
cl /nologo /EHsc /std:c++17 /O2 /DWIN32 /D_WINDOWS /I F:\rawrxd\include /I F:\rawrxd\src\win32app ^
  ..\harness\terminal_conpty_capture.cpp F:\rawrxd\src\win32app\Win32TerminalManager.cpp ^
  /Fe:terminal_conpty_capture.exe /link user32.lib kernel32.lib advapi32.lib
exit /b %ERRORLEVEL%
