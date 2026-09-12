@echo off
setlocal
where cl >nul 2>nul
if errorlevel 1 (
  echo ERROR: run from an x64 Native Tools Command Prompt or call vcvars64.bat first.
  exit /b 1
)
cl /nologo /O2 /EHsc /std:c++17 /W4 /I src ^
  src\deep2_dual_fabric.cpp src\deep2_dual_fabric_smoke.cpp ^
  /Fe:deep2_dual_fabric_smoke.exe
if errorlevel 1 exit /b %errorlevel%
deep2_dual_fabric_smoke.exe
exit /b %errorlevel%
