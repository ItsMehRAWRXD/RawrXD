@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d F:\~dev\rawrxd
if not exist bld_q6ktrace\q4k mkdir bld_q6ktrace\q4k
cl /nologo /std:c++17 /EHsc /O2 /W3 /I src /I "C:\VulkanSDK\1.4.357.0\Include" /Fe:bld_q6ktrace\q4k_gate.exe tools\q4k_gemv_parity.cpp src\gguf_loader.cpp /Fo:bld_q6ktrace\q4k\ 2>&1 | findstr /V "C4267 C4189 C4996"
if errorlevel 1 exit /b 1
bld_q6ktrace\q4k_gate.exe "F:\~dev\qwen2.5-coder-1.5b-base.gguf"