@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d F:\~dev\rawrxd
if not exist bld_q6ktrace\sweep mkdir bld_q6ktrace\sweep
cl /nologo /std:c++17 /EHsc /O2 /W3 /I src /Fe:bld_q6ktrace\real_q6k_gemv_parity.exe real_q6k_gemv_parity.cpp src\gguf_loader.cpp /Fo:bld_q6ktrace\sweep\ 2>&1 | findstr /V "C4267 C4189 C4996"
if errorlevel 1 exit /b 1
bld_q6ktrace\real_q6k_gemv_parity.exe "F:\~dev\qwen2.5-coder-1.5b-base.gguf"