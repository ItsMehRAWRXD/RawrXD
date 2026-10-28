@echo off
setlocal EnableExtensions
set EVID=%~dp0
set ROOT=g:\~dev\rawrxd
set BT=%ROOT%\build_win32ide_link001
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

set CAMOBJ=%BT%\RawrXD_Camellia256.obj
set AUTH_E2E=%ROOT%\evidence\CAMELLIA_AUTH_ASM_BIND_001\RawrXD_Camellia256_e2e.obj
if exist "%AUTH_E2E%" set CAMOBJ=%AUTH_E2E%
if exist "%EVID%RawrXD_Camellia256_e2e.obj" set CAMOBJ=%EVID%RawrXD_Camellia256_e2e.obj
if not exist "%CAMOBJ%" ( echo MISSING Camellia256.obj & exit /b 2 )

echo CAMOBJ=%CAMOBJ%
echo Compiling wired batch_005 (SOURCE_WIRED get_baseline)...

"%CL_EXE%" /nologo /O2 /EHsc /std:c++17 /c /DWIN32 /D_WINDOWS /DRAWR_HAS_MASM=1 /I%ROOT%\src\core /I%ROOT%\include /I%ROOT% /I%ROOT%\src /I%INC_MSVC% /I%INC_UCRT% /I%INC_UM% /I%INC_SHARED% /Fo%EVID%batch_005_hmac.obj %ROOT%\src\core\unlinked_symbols_batch_005.cpp
if errorlevel 1 ( echo COMPILE_FAIL batch_005 & exit /b 1 )

"%CL_EXE%" /nologo /O2 /TC /EHa /c /I%INC_MSVC% /I%INC_UCRT% /I%INC_UM% /I%INC_SHARED% runtime_hmac_product_smoke.c /Foruntime_hmac_product_smoke.obj
if errorlevel 1 ( echo COMPILE_FAIL smoke & exit /b 1 )

"%CL_EXE%" /nologo /O2 /TC /c /I%INC_MSVC% /I%INC_UCRT% /I%INC_UM% /I%INC_SHARED% mag_stubs.c /Fomag_stubs.obj
if errorlevel 1 ( echo COMPILE_FAIL mag_stubs & exit /b 1 )

"%CL_EXE%" /nologo /O2 /TC /c /I%INC_MSVC% /I%INC_UCRT% /I%INC_UM% /I%INC_SHARED% ods_stub.c /Foods_stub.obj
if errorlevel 1 ( echo COMPILE_FAIL ods_stub & exit /b 1 )

"%LINK_EXE%" /nologo /SUBSYSTEM:CONSOLE /FORCE:MULTIPLE /OUT:runtime_hmac_product_smoke.exe runtime_hmac_product_smoke.obj batch_005_hmac.obj mag_stubs.obj ods_stub.obj "%CAMOBJ%" /LIBPATH:%LIB_MSVC% /LIBPATH:%LIB_UCRT% /LIBPATH:%LIB_UM% kernel32.lib advapi32.lib bcrypt.lib user32.lib
if errorlevel 1 ( echo LINK_FAIL & exit /b 1 )
echo BUILD_OK
exit /b 0
