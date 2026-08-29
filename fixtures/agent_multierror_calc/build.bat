@echo off
cl /nologo /EHsc /std:c++20 add.cpp mul.cpp main.cpp /Fe:calc_ok.exe
if errorlevel 1 exit /b 1
calc_ok.exe
exit /b %ERRORLEVEL%
