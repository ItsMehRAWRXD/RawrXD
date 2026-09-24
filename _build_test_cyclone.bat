@echo off
setlocal

:: MSVC 2022 x64 native tools
set VCVARS="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if exist %VCVARS% goto :found
set VCVARS="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if exist %VCVARS% goto :found
set VCVARS="C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
if exist %VCVARS% goto :found
set VCVARS="C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
:found

call %VCVARS%
cl.exe /EHsc /std:c++17 /I f:\~dev\rawrxd\src\deep2 f:\~dev\rawrxd\src\deep2\CycloneScheduler_test.cpp f:\~dev\rawrxd\src\deep2\CycloneScheduler.cpp /Fe:f:\~dev\_test_cyclone.exe > f:\~dev\_test_cyclone_build.txt 2>&1
if errorlevel 1 (
    echo BUILD_FAILED
    exit /b 1
)
f:\~dev\_test_cyclone.exe > f:\~dev\_test_cyclone_run.txt 2>&1
if errorlevel 1 (
    echo RUN_FAILED
    exit /b 1
)
echo ALL_OK
