@echo off
setlocal
if "%VCToolsInstallDir%"=="" (
  echo Run from "x64 Native Tools Command Prompt for VS".
  exit /b 2
)
cl /nologo /TC /O2 /GS- /W4 /c ds671_route_load.c
if errorlevel 1 exit /b 1
cl /nologo /TC /O2 /W4 smoke_portable.c ds671_route_load.obj /Fe:ds671_route_load_smoke.exe
if errorlevel 1 exit /b 1
ds671_route_load_smoke.exe
