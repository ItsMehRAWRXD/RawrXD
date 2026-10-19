@echo off
setlocal
where cl >nul 2>nul
if errorlevel 1 (
  echo MSVC cl.exe not found. Run from an x64 Native Tools prompt or call vcvars64.bat first.
  exit /b 1
)

if not exist build mkdir build

cl /nologo /std:c++17 /O2 /EHsc- /GR- /W4 ^
  /Iinclude ^
  src\d2_sweep_amortizer.cpp ^
  src\d2_residency.cpp ^
  src\selftest.cpp ^
  /Fe:build\d2_sweep_amortizer_selftest.exe

if errorlevel 1 exit /b %errorlevel%

build\d2_sweep_amortizer_selftest.exe
exit /b %errorlevel%
