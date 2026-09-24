@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" > nul
cl /EHsc /std:c++17 /W3 /O2 /I "f:\~dev\rawrxd\src" "f:\~dev\rawrxd\tests\deep2\ProductionProfiler_test.cpp" "f:\~dev\rawrxd\src\deep2\ProductionProfiler.cpp" /Fe:"f:\~dev\rawrxd\tests\deep2\ProductionProfiler_test.exe"
