@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d F:\~dev\rawrxd
cl /nologo /std:c++17 /EHsc /O2 /W3 /I src /Fe:bld_q6ktrace\q6k_live_block_trace.exe q6k_live_block_trace.cpp src\gguf_loader.cpp /Fo:bld_q6ktrace\
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /EHsc /O2 /W3 /I src /Fe:bld_q6ktrace\fp16_probe.exe fp16_probe.cpp src\gguf_loader.cpp /Fo:bld_q6ktrace\
if errorlevel 1 exit /b 1
bld_q6ktrace\fp16_probe.exe
echo ---------------- Q6K LIVE BLOCK TRACE ----------------
bld_q6ktrace\q6k_live_block_trace.exe "F:\~dev\qwen2.5-coder-1.5b-base.gguf"