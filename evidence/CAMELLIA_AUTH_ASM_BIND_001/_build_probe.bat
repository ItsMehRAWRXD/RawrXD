@echo off
setlocal EnableExtensions
set EVID=%~dp0
set BT=g:\~dev\rawrxd\build_win32ide_link001
set SDKVER=10.0.26100.0
for %%I in ("C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe") do set CL_EXE=%%~sI
for %%I in ("C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe") do set LINK_EXE=%%~sI
for %%I in ("C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\include") do set INC_MSVC=%%~sI
for %%I in ("C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\lib\x64") do set LIB_MSVC=%%~sI
for %%I in ("C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\ucrt") do set INC_UCRT=%%~sI
for %%I in ("C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\um") do set INC_UM=%%~sI
for %%I in ("C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\shared") do set INC_SHARED=%%~sI
for %%I in ("C:\Program Files (x86)\Windows Kits\10\Lib\%SDKVER%\ucrt\x64") do set LIB_UCRT=%%~sI
for %%I in ("C:\Program Files (x86)\Windows Kits\10\Lib\%SDKVER%\um\x64") do set LIB_UM=%%~sI
cd /d "%EVID%"
set CL=
set LINK=
set CAMOBJ=%BT%\RawrXD_Camellia256.obj
if exist "%EVID%RawrXD_Camellia256_e2e.obj" set CAMOBJ=%EVID%RawrXD_Camellia256_e2e.obj
echo CAMOBJ=%CAMOBJ%
"%CL_EXE%" /nologo /O2 /TC /EHa /c /I%INC_MSVC% /I%INC_UCRT% /I%INC_UM% /I%INC_SHARED% runtime_auth_e2e_probe.c /Foruntime_auth_e2e_probe.obj
if errorlevel 1 exit /b 1
"%LINK_EXE%" /nologo /SUBSYSTEM:CONSOLE /OUT:runtime_auth_e2e_probe.exe runtime_auth_e2e_probe.obj "%CAMOBJ%" /LIBPATH:%LIB_MSVC% /LIBPATH:%LIB_UCRT% /LIBPATH:%LIB_UM% kernel32.lib advapi32.lib bcrypt.lib
if errorlevel 1 exit /b 1
echo PROBE_BUILD_OK
runtime_auth_e2e_probe.exe
echo PROBE_EXIT=%ERRORLEVEL%
exit /b %ERRORLEVEL%
