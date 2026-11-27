@echo off
REM Build the deterministic production-controller self-test (model-free).
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%~dp0.."
if not exist bin mkdir bin
cl /nologo /std:c++17 /EHsc /I include /I src tools\agent_controller_selftest.cpp src\agent\agent_controller.cpp /Fe:bin\agent_controller_selftest.exe /link winhttp.lib
exit /b %errorlevel%