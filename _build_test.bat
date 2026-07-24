@echo off
call "%ProgramFiles%\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

if errorlevel 1 (
    echo VS environment failed
    exit /b 1
)

set "INCLUDE=%INCLUDE%;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared"

echo [4/4] Compiling test executable...
cl /O2 /std:c++20 /EHsc /arch:AVX512 /I src tests\test_fix5a_kv_cache.cpp bin\RawrXD_KVCache_Layout.obj bin\RawrXD_DeterministicPerformance.obj /Fe:bin\test_fix5a_kv_cache.exe /link /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"

if errorlevel 1 (
    echo ERROR: Test compilation failed
    exit /b 1
)
echo     OK: test_fix5a_kv_cache.exe
