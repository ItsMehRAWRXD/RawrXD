@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0"
cl /nologo /EHsc /O2 /std:c++17 /Fe:test_rxow.exe test_rxow.cpp RxRunStateHooks.cpp
if errorlevel 1 exit /b 1
test_rxow.exe
exit /b %ERRORLEVEL%
