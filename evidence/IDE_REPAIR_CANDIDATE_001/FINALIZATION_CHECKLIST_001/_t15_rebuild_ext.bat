@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || call "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cd /d F:\rawrxd\build_tip_ext_host_001
ninja RawrXD-Win32IDE-Native-Ext
echo NINJA_EXIT=%ERRORLEVEL%
certutil -hashfile bin\RawrXD-Win32IDE-Native-Ext.exe SHA256
endlocal
