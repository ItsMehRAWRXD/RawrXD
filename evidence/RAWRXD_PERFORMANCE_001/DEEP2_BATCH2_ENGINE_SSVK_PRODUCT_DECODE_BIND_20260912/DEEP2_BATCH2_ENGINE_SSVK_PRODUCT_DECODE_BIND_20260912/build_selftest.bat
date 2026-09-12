@echo off
setlocal
cl /nologo /EHsc /O2 /W4 /std:c++17 selftest.cpp Deep2SsVkProductBind.cpp /Fe:selftest.exe
if errorlevel 1 exit /b %errorlevel%
selftest.exe
