@echo off
setlocal
if not exist build mkdir build
cl /nologo /std:c++17 /O2 /EHsc /I src smoke.cpp src\*.cpp /Fe:build\d2_missing15_smoke.exe
if errorlevel 1 exit /b %errorlevel%
build\d2_missing15_smoke.exe
