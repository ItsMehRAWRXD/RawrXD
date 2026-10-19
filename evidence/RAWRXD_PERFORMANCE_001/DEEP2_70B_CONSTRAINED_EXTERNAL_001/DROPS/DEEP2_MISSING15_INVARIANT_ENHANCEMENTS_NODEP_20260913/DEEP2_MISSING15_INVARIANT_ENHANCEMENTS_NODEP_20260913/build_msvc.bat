@echo off
setlocal
cl /nologo /O2 /W4 /TC selftest.c /Fe:selftest.exe
if errorlevel 1 exit /b 1
selftest.exe
exit /b %errorlevel%
