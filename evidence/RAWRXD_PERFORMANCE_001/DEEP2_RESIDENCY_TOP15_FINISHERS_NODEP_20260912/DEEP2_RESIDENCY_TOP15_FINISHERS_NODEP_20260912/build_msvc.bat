@echo off
setlocal
where cl >nul 2>nul
if errorlevel 1 exit /b 1
cl /nologo /O2 /W4 /WX /std:c11 /TC /Iinclude ^
  src\d2_residency_finishers.c tests\selftest.c /Fe:selftest.exe
if errorlevel 1 exit /b %errorlevel%
selftest.exe
exit /b %errorlevel%
