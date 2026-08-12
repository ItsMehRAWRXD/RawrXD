@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\B009

REM Find kernel32.lib
dir /s /b "C:\Program Files (x86)\Windows Kits\10\Lib\kernel32.lib" 2>nul > _libpath.txt
dir /s /b "C:\Program Files\Windows Kits\10\Lib\kernel32.lib" 2>nul >> _libpath.txt

set /p K32= < _libpath.txt
set K32=%K32:kernel32.lib=%

echo Found lib path: %K32%
echo LIB=%LIB%

ml64.exe /c /Zi /FoNegativeSpaceProfiler.obj NegativeSpaceProfiler.asm
cl.exe /O2 /EHsc /Zi /W4 /FeB009_ProfilerTest.exe B009_ProfilerTest.cpp NegativeSpaceProfiler.obj /link /LIBPATH:"%K32%"
B009_ProfilerTest.exe
