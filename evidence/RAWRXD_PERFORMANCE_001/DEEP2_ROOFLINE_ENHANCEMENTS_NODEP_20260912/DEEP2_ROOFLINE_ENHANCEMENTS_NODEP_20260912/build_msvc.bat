@echo off
setlocal
cl /nologo /O2 /W4 /WX /TC selftest.c d2_roofline.c /Fe:selftest.exe
if errorlevel 1 exit /b %errorlevel%
selftest.exe
exit /b %errorlevel%
