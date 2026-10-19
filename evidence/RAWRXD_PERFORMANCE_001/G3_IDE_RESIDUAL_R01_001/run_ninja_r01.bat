@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d "g:\~dev\rawrxd\build-fd"
ninja -j1 bin/RawrXD-Win32IDE.exe > "g:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_IDE_RESIDUAL_R01_001\ninja_detached_j1.txt" 2>&1
echo EXIT=%ERRORLEVEL%>> "g:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_IDE_RESIDUAL_R01_001\ninja_detached_j1.txt"
