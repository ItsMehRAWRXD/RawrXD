@echo off
setlocal
if "%VCToolsInstallDir%"=="" (
  call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
)
if "%VCToolsInstallDir%"=="" (
  echo Run from x64 Native Tools or ensure BuildTools vcvars64.bat exists.
  exit /b 2
)
cd /d "%~dp0"
set CCFLAGS=/nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS

cl %CCFLAGS% /TC /c ds671_route_load.c
if errorlevel 1 exit /b 1
cl %CCFLAGS% /TC /c ds671_tensor_names.c
if errorlevel 1 exit /b 1
cl %CCFLAGS% /TC /c ds671_tensor_io.c
if errorlevel 1 exit /b 1
cl %CCFLAGS% /TC /c ds671_tensor_cb.c
if errorlevel 1 exit /b 1
cl %CCFLAGS% /TC /c ds671_gguf_rd.c
if errorlevel 1 exit /b 1
cl %CCFLAGS% /TC /c ds671_gguf_index.c
if errorlevel 1 exit /b 1

cl %CCFLAGS% /TC smoke_portable.c /link ds671_route_load.obj /OUT:ds671_route_load_smoke.exe
if errorlevel 1 exit /b 1
ds671_route_load_smoke.exe
if errorlevel 1 exit /b 1

cl %CCFLAGS% /TC smoke_adapter.c /link ds671_route_load.obj ds671_tensor_names.obj ds671_tensor_io.obj ds671_tensor_cb.obj /OUT:ds671_adapter_smoke.exe
if errorlevel 1 exit /b 1
ds671_adapter_smoke.exe
if errorlevel 1 exit /b 1

cl %CCFLAGS% /TC smoke_index_bind.c /link ds671_tensor_names.obj ds671_gguf_rd.obj ds671_gguf_index.obj /OUT:ds671_index_bind_smoke.exe
if errorlevel 1 exit /b 1
ds671_index_bind_smoke.exe
if errorlevel 1 exit /b 1

echo DS671_ADAPTER_BUILD=PASS
exit /b 0
