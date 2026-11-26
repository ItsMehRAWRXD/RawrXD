@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%~dp0"
cl /nologo /std:c++17 /EHsc /O2 sysmon.cpp /Fe:sysmon.exe /link /SUBSYSTEM:WINDOWS user32.lib gdi32.lib
exit /b %errorlevel%