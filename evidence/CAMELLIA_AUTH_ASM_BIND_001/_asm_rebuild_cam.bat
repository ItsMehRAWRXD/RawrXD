@echo off
setlocal EnableExtensions
set EVID=%~dp0
set SRC=g:\~dev\rawrxd\src\asm
for %%I in ("C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\ml64.exe") do set ML64=%%~sI
cd /d "%EVID%"
if not exist "%ML64%" (
  echo MISSING ml64
  exit /b 2
)
echo ML64=%ML64%
"%ML64%" /nologo /c /Fo"RawrXD_Camellia256_e2e.obj" "%SRC%\RawrXD_Camellia256.asm" > ml64_cam_e2e.out 2>&1
echo ML64_CAM_EXIT=%ERRORLEVEL%
type ml64_cam_e2e.out
if errorlevel 1 exit /b 1
"%ML64%" /nologo /c /Fo"RawrXD_Camellia256_Auth_e2e.obj" "%SRC%\RawrXD_Camellia256_Auth.asm" > ml64_auth_e2e.out 2>&1
echo ML64_AUTH_EXIT=%ERRORLEVEL%
type ml64_auth_e2e.out
if errorlevel 1 exit /b 1
echo ASM_REBUILD_OK
exit /b 0
