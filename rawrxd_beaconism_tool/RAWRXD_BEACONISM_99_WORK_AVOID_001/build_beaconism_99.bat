@echo off
setlocal
where cl >nul 2>nul
if errorlevel 1 (
  echo ERROR: cl.exe not found. Run from a Visual Studio x64 Native Tools prompt.
  exit /b 1
)

cl /nologo /std:c++20 /O2 /EHsc /W4 /permissive- ^
  beaconism_99.cpp beaconism_99_demo.cpp ^
  /Fe:beaconism_99_demo.exe

if errorlevel 1 exit /b 1
beaconism_99_demo.exe
exit /b %errorlevel%
