@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d F:\~dev\rawrxd
cl /nologo /std:c++17 /EHsc /O2 /W3 /I src /Fe:bld_q6ktrace\q6k_row_decisive.exe q6k_row_decisive.cpp src\gguf_loader.cpp src\rawrxd_cpu_math.cpp /Fo:bld_q6ktrace\rowdec\ /link /FORCE:OVERWRITE 2>&1 | findstr /V "C4267 C4305 C4189"
if errorlevel 1 exit /b 1
bld_q6ktrace\q6k_row_decisive.exe "F:\~dev\qwen2.5-coder-1.5b-base.gguf"