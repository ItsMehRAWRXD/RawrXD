@echo off
setlocal EnableExtensions
set EVID=%~dp0
cd /d "%EVID%"
set CDB=
if exist "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe" set CDB=C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe
if exist "C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe" set CDB=C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe
if "%CDB%"=="" (
  echo NO_CDB
  exit /b 2
)
echo CDB=%CDB%
"%CDB%" -g -G -c ".ecxr; u @rip L20; k; q" runtime_auth_e2e_probe.exe > RUNTIME_E2E_cdb_set_key.txt 2>&1
type RUNTIME_E2E_cdb_set_key.txt
exit /b 0
