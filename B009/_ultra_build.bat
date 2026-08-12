@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\B009
set "LIB=%LIB%;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
ml64 /c /FoNegativeSpaceProfiler.obj NegativeSpaceProfiler.asm
cl /O2 /EHsc /Feultra_minimal.exe ultra_minimal.cpp NegativeSpaceProfiler.obj
ultra_minimal.exe
