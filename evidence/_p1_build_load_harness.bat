@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d "F:\~dev\rawrxd\build-win32ide-p1" || exit /b 1
cmake "F:\~dev\rawrxd" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DRAWRXD_BUILD_WIN32IDE=ON -DRAWRXD_BUILD_RAWRENGINE=OFF -DRAWRXD_ALLOW_AGENTIC_STUB_FALLBACK=ON
if errorlevel 1 exit /b 1
ninja p1_cpu_loadmodel_harness
exit /b %ERRORLEVEL%
