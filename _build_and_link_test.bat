@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd

set INCLUDES=/I"d:\rawrxd\src\deep2" /I"d:\rawrxd\include"
set FLAGS=/nologo /EHsc /W4 /O2 /std:c++17 /D_CRT_SECURE_NO_WARNINGS /DKV_CACHE_EQUIVALENCE_TEST_MAIN=1

cl %FLAGS% %INCLUDES% /c "src\deep2\KVCache.cpp" /Fo"build_validate\KVCache.obj"
cl %FLAGS% %INCLUDES% /c "src\deep2\ToroidalKVCache.cpp" /Fo"build_validate\ToroidalKVCache.obj"
cl %FLAGS% %INCLUDES% /c "src\deep2\Chamber.cpp" /Fo"build_validate\Chamber.obj"
cl %FLAGS% %INCLUDES% /c "src\deep2\LegacyKVCacheAdapter.cpp" /Fo"build_validate\LegacyKVCacheAdapter.obj"
cl %FLAGS% %INCLUDES% /c "src\deep2\ToroidalKVCacheAdapter.cpp" /Fo"build_validate\ToroidalKVCacheAdapter.obj"
cl %FLAGS% %INCLUDES% /c "src\deep2\KVCacheEquivalenceTest.cpp" /Fo"build_validate\KVCacheEquivalenceTest.obj"

link /nologo /out:"build_validate\KVCacheEquivalenceTest.exe" ^
  build_validate\KVCacheEquivalenceTest.obj ^
  build_validate\LegacyKVCacheAdapter.obj ^
  build_validate\ToroidalKVCacheAdapter.obj ^
  build_validate\KVCache.obj ^
  build_validate\ToroidalKVCache.obj ^
  build_validate\Chamber.obj

echo Build complete. Checking for executable...
if exist "build_validate\KVCacheEquivalenceTest.exe" (
  echo SUCCESS: KVCacheEquivalenceTest.exe built
  "build_validate\KVCacheEquivalenceTest.exe"
) else (
  echo FAILED: executable not found
)
