@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /W4 /I src/deep2 /Fe:k2_kv_cache_invariants.exe tests/k2_kv_cache_invariants.cpp
if errorlevel 1 exit /b 1

k2_kv_cache_invariants.exe
if errorlevel 1 exit /b 1

echo k2_kv_cache_invariants passed