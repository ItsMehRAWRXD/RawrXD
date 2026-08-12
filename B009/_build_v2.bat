@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\B009
set "LIB=%LIB%;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
ml64 /c /FoNegativeSpaceProfiler_v2.obj NegativeSpaceProfiler_v2.asm
cl /O2 /EHsc /FeB009_ProfilerTest_v2.exe B009_ProfilerTest_v2.cpp NegativeSpaceProfiler_v2.obj
B009_ProfilerTest_v2.exe
