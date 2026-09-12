@echo off
setlocal
cl /nologo /O2 /W4 /std:c11 /TC d2_generators.c selftest.c /Fe:selftest.exe
if errorlevel 1 exit /b %errorlevel%
selftest.exe
