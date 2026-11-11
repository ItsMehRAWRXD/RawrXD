@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d F:\rawrxd\build_ide || exit /b 1
ninja deep2_engine_lib rawr-reap-replay || exit /b 1
call F:\rawrxd\_run_lite_gate2_now.bat
exit /b %ERRORLEVEL%
