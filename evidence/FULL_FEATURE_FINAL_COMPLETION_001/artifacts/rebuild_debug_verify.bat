@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d F:\rawrxd\build_tip_debug_001
ninja debug_backend_verify debuggee_fixture
exit /b %ERRORLEVEL%
