@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 2
cmake --build F:\rawrxd\build_5os_win --target rawrxd_link --config Release --parallel 4
exit /b %ERRORLEVEL%
