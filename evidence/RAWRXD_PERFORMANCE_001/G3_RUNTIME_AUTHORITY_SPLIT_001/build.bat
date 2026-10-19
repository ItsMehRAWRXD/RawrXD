@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd\build-fd
ninja deep2_streamer_parity 2>&1
echo NINJA_EXIT=%ERRORLEVEL%