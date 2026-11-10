@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 2
set "EV=F:\rawrxd\evidence\RAWRXD_SOVEREIGN_LINKER_CERT_001"
set "MAN=%EV%\obj_manifest.txt"
set "LIST=%EV%\obj_candidate_list.txt"
set "MISS=%EV%\obj_not_found.txt"
set "OUT=%EV%\native_object_inventory_raw.txt"
echo === NATIVE OBJ INVENTORY (manifest only, no dir /s) === > "%OUT%"
if exist "%LIST%" del "%LIST%"
if exist "%MISS%" del "%MISS%"
for /f "usebackq delims=" %%P in ("%MAN%") do (
  if exist "%%P" (
    echo %%P>> "%LIST%"
    echo ---- FOUND %%P ---->> "%OUT%"
    dumpbin /HEADERS "%%P" >> "%OUT%" 2>&1
    dumpbin /SYMBOLS "%%P" >> "%OUT%" 2>&1
    dumpbin /RELOCATIONS "%%P" >> "%OUT%" 2>&1
  ) else (
    echo %%P>> "%MISS%"
    echo ---- NOT_FOUND %%P ---->> "%OUT%"
  )
)
echo LIST_DONE>> "%OUT%"
powershell -NoProfile -ExecutionPolicy Bypass -File "%EV%\classify_inventory.ps1"
exit /b %ERRORLEVEL%
