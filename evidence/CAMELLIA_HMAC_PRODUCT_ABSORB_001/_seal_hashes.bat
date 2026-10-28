@echo off
setlocal EnableExtensions
set EVID=%~dp0
set BT=G:\~dev\rawrxd\build_win32ide_link001
set LOG=%EVID%logs
if not exist "%LOG%" mkdir "%LOG%"

copy /Y "%BT%\RawrXD_Camellia256.obj" "%EVID%RawrXD_Camellia256.obj" >nul
copy /Y "%BT%\RawrXD_Watchdog.obj" "%EVID%RawrXD_Watchdog.obj" >nul

certutil -hashfile "%BT%\bin\RawrXD-Win32IDE.exe" SHA256 > "%LOG%\exe_sha_final.txt"
certutil -hashfile "%BT%\RawrXD_Camellia256.obj" SHA256 > "%LOG%\cam_obj_sha_postlink.txt"
certutil -hashfile "%BT%\RawrXD_Watchdog.obj" SHA256 > "%LOG%\wd_obj_sha_postlink.txt"

echo === EXE ===
type "%LOG%\exe_sha_final.txt"
for %%A in ("%BT%\bin\RawrXD-Win32IDE.exe") do echo EXE_SIZE=%%~zA
echo === CAM OBJ ===
type "%LOG%\cam_obj_sha_postlink.txt"
for %%A in ("%BT%\RawrXD_Camellia256.obj") do echo CAM_SIZE=%%~zA
echo === WD OBJ ===
type "%LOG%\wd_obj_sha_postlink.txt"
for %%A in ("%BT%\RawrXD_Watchdog.obj") do echo WD_SIZE=%%~zA
echo SEAL_HASHES_OK
exit /b 0
