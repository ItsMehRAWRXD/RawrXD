@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "g:\~dev\rawrxd\evidence\RAWRXD_ALL_BACKENDS_COMPLETE_001\W7_STRATA_HIP_OLLAMA_001\probe"
cl /nologo /EHsc /O2 /Fe:hip_backend_minimal.exe "g:\~dev\rawrxd\src\backend\hip_backend_minimal.cpp" > hip_bench_build.txt 2>&1
if errorlevel 1 exit /b 1
hip_backend_minimal.exe > hip_bench.out.txt 2>&1
echo hip_bench_exit=%ERRORLEVEL%>> hip_bench.out.txt
