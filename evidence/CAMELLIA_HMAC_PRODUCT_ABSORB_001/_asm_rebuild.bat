@echo off
setlocal EnableExtensions
set EVID=%~dp0
set ROOT=G:\~dev\rawrxd
set BT=%ROOT%\build_win32ide_link001
set SRC=%ROOT%\src\asm
set LOG=%EVID%logs
if not exist "%LOG%" mkdir "%LOG%"

for %%I in ("C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\ml64.exe") do set ML64=%%~sI
if not exist "%ML64%" (
  echo MISSING ml64
  exit /b 2
)

echo ML64=%ML64%
echo Assembling RawrXD_Camellia256.asm into product bind + evidence copy...
"%ML64%" /nologo /c /Zi /Zd /I "%SRC%" /Fo"%BT%\RawrXD_Camellia256.obj" "%SRC%\RawrXD_Camellia256.asm" > "%LOG%\ml64_camellia.out" 2>&1
set RC_CAM=%ERRORLEVEL%
type "%LOG%\ml64_camellia.out"
echo ML64_CAM_EXIT=%RC_CAM%
if not "%RC_CAM%"=="0" exit /b 1
copy /Y "%BT%\RawrXD_Camellia256.obj" "%EVID%RawrXD_Camellia256.obj" >nul

echo Assembling RawrXD_Watchdog.asm into product bind + evidence copy...
"%ML64%" /nologo /c /Zi /Zd /I "%SRC%" /Fo"%BT%\RawrXD_Watchdog.obj" "%SRC%\RawrXD_Watchdog.asm" > "%LOG%\ml64_watchdog.out" 2>&1
set RC_WD=%ERRORLEVEL%
type "%LOG%\ml64_watchdog.out"
echo ML64_WD_EXIT=%RC_WD%
if not "%RC_WD%"=="0" exit /b 1
copy /Y "%BT%\RawrXD_Watchdog.obj" "%EVID%RawrXD_Watchdog.obj" >nul

for %%A in ("%BT%\RawrXD_Camellia256.obj") do echo CAM_OBJ_SIZE=%%~zA
for %%A in ("%BT%\RawrXD_Watchdog.obj") do echo WD_OBJ_SIZE=%%~zA
certutil -hashfile "%BT%\RawrXD_Camellia256.obj" SHA256 > "%LOG%\cam_obj_sha.txt"
certutil -hashfile "%BT%\RawrXD_Watchdog.obj" SHA256 > "%LOG%\wd_obj_sha.txt"
echo ASM_REBUILD_OK
exit /b 0
