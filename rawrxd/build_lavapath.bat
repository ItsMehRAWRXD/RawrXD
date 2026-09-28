@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d F:\~dev\rawrxd
if not exist build\lavapath mkdir build\lavapath
cl /std:c++20 /EHsc /O2 /I src /I src\deep2 /I src\deep2\lavapath src\deep2\lavapath\DualStickStreamWindow.cpp /c /Fobuild\lavapath\DualStickStreamWindow.obj
cl /std:c++20 /EHsc /O2 /I src /I src\deep2 /I src\deep2\lavapath src\deep2\lavapath\DualStickStreamWindow_Emit.cpp /c /Fobuild\lavapath\DualStickStreamWindow_Emit.obj
cl /std:c++20 /EHsc /O2 /I src /I src\deep2 /I src\deep2\lavapath src\deep2\lavapath\DualStickStreamWindow_Acquire.cpp /c /Fobuild\lavapath\DualStickStreamWindow_Acquire.obj
cl /std:c++20 /EHsc /O2 /I src /I src\deep2 /I src\deep2\lavapath src\deep2\lavapath\DualStickEnvSnap.cpp /c /Fobuild\lavapath\DualStickEnvSnap.obj
echo DONE
