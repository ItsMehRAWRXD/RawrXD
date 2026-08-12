@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\B009
ml64 /c /FoMinimalProfiler.obj MinimalProfiler.asm
link /subsystem:console /entry:main MinimalProfiler.obj "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib" /out:MinimalProfiler.exe
MinimalProfiler.exe
