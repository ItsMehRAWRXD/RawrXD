@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
echo === RawrXD_ServeInference.dll ===
dumpbin /exports F:\rawrxd\deploy\RawrXD_ServeInference.dll | findstr RawrXD
echo === RawrXD_MultiWindow_Kernel.dll ===
dumpbin /exports F:\rawrxd\deploy\RawrXD_MultiWindow_Kernel.dll | findstr RawrXD