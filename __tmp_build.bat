@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd
ninja -f agentic_build/build.ninja -j1 bin/RawrXD-Win32IDE.exe
