@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd
cmake -S . -B build_validate -G Ninja -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl -DRAWRXD_ENABLE_TOROIDAL_KV=ON
cmake --build build_validate --target KVCacheEquivalenceTest 2>&1
