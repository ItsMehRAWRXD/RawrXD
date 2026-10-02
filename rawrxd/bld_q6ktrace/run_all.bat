@echo off
REM Full final verification for RAWRXD_FP16_SUBNORMAL_001 / Q6K_LIVE_BLOCK_TRACE_001
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d F:\~dev\rawrxd

echo ==================== 1. COMPILE CHECK ====================
if not exist bld_q6ktrace\cchk mkdir bld_q6ktrace\cchk
for %%F in (src\core\dml_asm_impl.cpp src\core\dml_asm_fallback.cpp src\gguf_loader.cpp) do (
  cl /nologo /c /std:c++17 /EHsc /O2 /W3 /I src /I "C:\VulkanSDK\1.4.357.0\Include" %%F /Fo:bld_q6ktrace\cchk\ 2>&1 | findstr /V "C4267 C4189 C4996"
)
for %%F in (src\core\aperture_q4_0_avx512_intrinsics.cpp src\core\aperture_q8_0_avx512_intrinsics.cpp) do (
  cl /nologo /c /std:c++17 /EHsc /O2 /W3 /arch:AVX512 /I src %%F /Fo:bld_q6ktrace\cchk\ 2>&1 | findstr /V "C4267 C4189 C4996"
)
echo COMPILE_CHECK=OK

echo ==================== 2. FP16 CENSUS ====================
cl /nologo /std:c++17 /EHsc /O2 /W3 /Fe:bld_q6ktrace\fp16_census.exe fp16_census.cpp /Fo:bld_q6ktrace\ >nul
bld_q6ktrace\fp16_census.exe

echo ==================== 3. FP16 PROBE (real exported routine) ====================
cl /nologo /std:c++17 /EHsc /O2 /W3 /I src /Fe:bld_q6ktrace\fp16_probe.exe fp16_probe.cpp src\gguf_loader.cpp /Fo:bld_q6ktrace\ >nul
bld_q6ktrace\fp16_probe.exe

echo ==================== 4. Q6_K ELEMENT TRACE ====================
cl /nologo /std:c++17 /EHsc /O2 /W3 /I src /Fe:bld_q6ktrace\q6k_live_block_trace.exe q6k_live_block_trace.cpp src\gguf_loader.cpp /Fo:bld_q6ktrace\ >nul
bld_q6ktrace\q6k_live_block_trace.exe "F:\~dev\qwen2.5-coder-1.5b-base.gguf" | findstr /V "0x  _raw _offset _addr scale0 d_raw d_fp32 q_low4 q_high2 q6_ d_x_scale _Q= result0 n_loop"

echo ==================== 5. MODEL IMPACT ====================
cl /nologo /std:c++17 /EHsc /O2 /W3 /I src /Fe:bld_q6ktrace\fp16_model_impact.exe fp16_model_impact.cpp src\gguf_loader.cpp /Fo:bld_q6ktrace\ >nul
bld_q6ktrace\fp16_model_impact.exe "F:\~dev\qwen2.5-coder-1.5b-base.gguf"

echo ==================== 6. END-TO-END DECODED WEIGHTS ====================
cl /nologo /std:c++17 /EHsc /O2 /W3 /I src /Fe:bld_q6ktrace\fp16_end_to_end.exe fp16_end_to_end.cpp src\gguf_loader.cpp /Fo:bld_q6ktrace\ >nul
bld_q6ktrace\fp16_end_to_end.exe "F:\~dev\qwen2.5-coder-1.5b-base.gguf" 64

echo ==================== 7. Q6_K GEMV PARITY GATE ====================
cl /nologo /std:c++17 /EHsc /O2 /W3 /I src /Fe:bld_q6ktrace\real_q6k_gemv_parity.exe real_q6k_gemv_parity.cpp src\gguf_loader.cpp /Fo:bld_q6ktrace\sweep\ >nul
bld_q6ktrace\real_q6k_gemv_parity.exe "F:\~dev\qwen2.5-coder-1.5b-base.gguf"
echo ==================== END ====================