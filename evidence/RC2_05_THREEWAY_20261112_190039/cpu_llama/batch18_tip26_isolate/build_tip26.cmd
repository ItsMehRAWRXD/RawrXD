@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d F:\rawrxd\build_reap || exit /b 1
ninja bin\aggregate_decode_single_smoke.exe
exit /b %ERRORLEVEL%
