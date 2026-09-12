@echo off
setlocal
where cl >nul 2>nul
if errorlevel 1 (
  echo cl.exe not found. Run from an x64 Native Tools prompt or call vcvars64.bat first.
  exit /b 1
)
if not exist build mkdir build
cl /nologo /TC /O2 /W4 /Iinclude ^
  src\d2_link15.c ^
  src\d2_link15_default_adapters.c ^
  src\selftest.c ^
  /Fe:build\d2_link15_selftest.exe
if errorlevel 1 exit /b %errorlevel%
build\d2_link15_selftest.exe
exit /b %errorlevel%
