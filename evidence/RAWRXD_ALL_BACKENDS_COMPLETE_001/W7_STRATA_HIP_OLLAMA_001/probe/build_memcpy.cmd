@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "g:\~dev\rawrxd\evidence\RAWRXD_ALL_BACKENDS_COMPLETE_001\W7_STRATA_HIP_OLLAMA_001\probe"
cl /nologo /O2 /Fe:hip_memcpy_bench.exe hip_memcpy_bench.c > hip_memcpy_build.txt 2>&1
if errorlevel 1 exit /b 1
hip_memcpy_bench.exe > hip_memcpy.out.txt 2>&1
echo exit=%ERRORLEVEL%>> hip_memcpy.out.txt
