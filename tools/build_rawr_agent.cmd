@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%~dp0.."
if not exist bin mkdir bin
cl /nologo /std:c++17 /EHsc /O2 /I src\deep2 tools\rawr_agent.cpp /Fe:bin\rawr_agent.exe /link winhttp.lib
exit /b %errorlevel%