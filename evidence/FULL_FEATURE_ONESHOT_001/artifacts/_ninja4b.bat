@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
echo AFTER_VCVARS
where ninja
where cl
cd /d "F:\rawrxd\build_tip_ext_host_001"
echo BEFORE_NINJA
ninja -d explain RawrXD-Win32IDE-Native-Ext
echo NINJA_RC=%ERRORLEVEL%
