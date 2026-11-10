@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
set "EV=F:\rawrxd\evidence\RAWRXD_SOVEREIGN_LINKER_CERT_001"
set "LINK=%EV%\p2_isolated\bin\rawrxd_link_isolated.exe"
set "OBJ=F:\rawrxd\build_reap\CMakeFiles\deep2_bench_tps.dir\tools\deep2_bench_tps.cpp.obj"
set "LOG=%EV%\native_reject_deep2.log"
echo === FAIL-CLOSED native Deep2 obj link === > "%LOG%"
"%LINK%" -o "%EV%\out\native_reject_deep2.exe" "%OBJ%" >> "%LOG%" 2>&1
echo EXIT=%ERRORLEVEL%>> "%LOG%"
type "%LOG%"
exit /b 0
