@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\B009

REM Add Windows SDK um\x64 lib path
set "LIB=%LIB%;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"

echo LIB=%LIB%

ml64.exe /c /Zi /FoNegativeSpaceProfiler.obj NegativeSpaceProfiler.asm
cl.exe /O2 /EHsc /Zi /W4 /FeB009_ProfilerTest.exe B009_ProfilerTest.cpp NegativeSpaceProfiler.obj
B009_ProfilerTest.exe
