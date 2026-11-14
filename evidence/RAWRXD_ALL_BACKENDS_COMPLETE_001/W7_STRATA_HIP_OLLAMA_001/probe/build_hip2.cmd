@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "g:\~dev\rawrxd\evidence\RAWRXD_ALL_BACKENDS_COMPLETE_001\W7_STRATA_HIP_OLLAMA_001\probe"
cl /nologo /O2 /Fe:hip_probe2.exe hip_probe2.c > hip_probe2_build.txt 2>&1
hip_probe2.exe > hip_probe2.out.txt 2>&1
echo hip2_exit=%ERRORLEVEL%>> hip_probe2.out.txt
