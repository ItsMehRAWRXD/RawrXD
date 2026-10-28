@echo off
setlocal EnableExtensions
set EVID=%~dp0
set BT=g:\~dev\rawrxd\build_win32ide_link001
set SDKVER=10.0.26100.0
rem Do NOT set env var CL= (MSVC option bag).

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
set _CL_=
set _LINK_=

set AUTHOBJ=%BT%\RawrXD_Camellia256_Auth.obj
set CAMOBJ=%BT%\RawrXD_Camellia256.obj
if exist "%EVID%RawrXD_Camellia256_Auth_e2e.obj" set AUTHOBJ=%EVID%RawrXD_Camellia256_Auth_e2e.obj
if exist "%EVID%RawrXD_Camellia256_e2e.obj" set CAMOBJ=%EVID%RawrXD_Camellia256_e2e.obj

if not exist "%AUTHOBJ%" ( echo MISSING Auth.obj & exit /b 2 )
if not exist "%CAMOBJ%" ( echo MISSING Camellia256.obj & exit /b 2 )

echo AUTHOBJ=%AUTHOBJ%
echo CAMOBJ=%CAMOBJ%

"%CL_EXE%" /nologo /O2 /TC /EHa /c /I%INC_MSVC% /I%INC_UCRT% /I%INC_UM% /I%INC_SHARED% runtime_auth_e2e_smoke.c /Foruntime_auth_e2e_smoke.obj
if errorlevel 1 ( echo COMPILE_FAIL smoke & exit /b 1 )
"%CL_EXE%" /nologo /O2 /TC /c /I%INC_MSVC% /I%INC_UCRT% /I%INC_UM% /I%INC_SHARED% ods_stub.c /Foods_stub.obj
if errorlevel 1 ( echo COMPILE_FAIL ods_stub & exit /b 1 )

"%LINK_EXE%" /nologo /SUBSYSTEM:CONSOLE /FORCE:MULTIPLE /OUT:runtime_auth_e2e_smoke.exe runtime_auth_e2e_smoke.obj ods_stub.obj "%AUTHOBJ%" "%CAMOBJ%" /LIBPATH:%LIB_MSVC% /LIBPATH:%LIB_UCRT% /LIBPATH:%LIB_UM% kernel32.lib advapi32.lib bcrypt.lib user32.lib
if errorlevel 1 ( echo LINK_FAIL & exit /b 1 )
echo BUILD_OK
exit /b 0
