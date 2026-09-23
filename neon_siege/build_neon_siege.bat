@echo off
setlocal
where cl >nul 2>nul
if errorlevel 1 (
  echo ERROR: cl.exe not found. Run from "x64 Native Tools Command Prompt for VS".
  exit /b 1
)

cl /nologo /std:c++17 /EHsc /O2 /DUNICODE /D_UNICODE NeonSiege.cpp ^
  /link /SUBSYSTEM:WINDOWS user32.lib gdi32.lib d3d11.lib dxgi.lib d3dcompiler.lib ^
  /OUT:NeonSiege.exe

if errorlevel 1 exit /b 1
echo BUILD=PASS
echo OUTPUT=%CD%\NeonSiege.exe
