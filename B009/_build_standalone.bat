@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\B009
set "LIB=%LIB%;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
ml64 /c /FoStandaloneProfiler.obj StandaloneProfiler.asm
link /subsystem:console /entry:main StandaloneProfiler.obj "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib" /out:StandaloneProfiler.exe
StandaloneProfiler.exe
