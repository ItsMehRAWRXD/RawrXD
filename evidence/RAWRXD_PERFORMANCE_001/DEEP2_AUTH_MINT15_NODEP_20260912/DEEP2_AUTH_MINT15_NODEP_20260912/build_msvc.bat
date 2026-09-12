@echo off
setlocal
where cl >nul 2>nul
if errorlevel 1 (
  echo cl.exe not found. Run from an x64 Native Tools prompt.
  exit /b 1
)
if not exist build mkdir build
cl /nologo /std:c++17 /O2 /W4 /EHsc- /GR- ^
  /Iinclude ^
  src\d2_authority_mint15.cpp ^
  src\selftest.cpp ^
  /Fe:build\d2_authority_mint15_selftest.exe
if errorlevel 1 exit /b %errorlevel%
build\d2_authority_mint15_selftest.exe
exit /b %errorlevel%
