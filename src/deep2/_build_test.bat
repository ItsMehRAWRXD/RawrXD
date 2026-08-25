@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
set SRC=d:\rawrxd\src\deep2
set INC=d:\rawrxd\src\deep2
set OUT=d:\rawrxd\src\deep2\KVCacheEquivalenceTest.exe

cl /nologo /std:c++17 /I"%INC%" /EHsc /W4 /O2 /Fe"%OUT%" ^
  "%SRC%\KVCacheEquivalenceTest.cpp" ^
  "%SRC%\LegacyKVCacheAdapter.cpp" ^
  "%SRC%\ToroidalKVCacheAdapter.cpp" ^
  "%SRC%\KVCache.cpp" ^
  "%SRC%\ToroidalKVCache.cpp" ^
  "%SRC%\Chamber.cpp" ^
  /D KV_CACHE_EQUIVALENCE_TEST_MAIN=1
