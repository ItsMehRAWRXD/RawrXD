@echo off
call "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cl /nologo /c /std:c++17 /I"d:\rawrxd\src\deep2" /I"d:\rawrxd\include" /EHsc /W4 /WX "d:\rawrxd\src\deep2\ToroidalKVCache.cpp" /Fo"d:\rawrxd\src\deep2\ToroidalKVCache_test.obj"
cl /nologo /c /std:c++17 /I"d:\rawrxd\src\deep2" /I"d:\rawrxd\include" /EHsc /W4 /WX "d:\rawrxd\src\deep2\Chamber.cpp" /Fo"d:\rawrxd\src\deep2\Chamber_test.obj"
