@echo off
REM =====================================================================================
REM Subsystem: Standalone Native Binary Compilation Engine
REM Targets: MSVC cl.exe and link.exe directly via standard Visual Studio x64 Native Tools
REM =====================================================================================

set OUT_DIR=.\dist
if not exist %OUT_DIR% mkdir %OUT_DIR%

echo [*] Initializing Bare-Metal Standalone Compilation...

REM MASM Module Path
set MASM_PATH=..\..\..\RawrXD-production-lazy-init\src\masm\final-ide

REM Compile MASM modules first
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\masm_core_thread_affinity.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\masm_core_transform_aes_ni.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\masm_transform_ring_buffer.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\masm_core_gemv_avx512.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\masm_7800x3d_unmethoded.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\masm_core_profiler.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\engineering_unreverse_core_extension.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\masm_host_zero_engineer.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\masm_dual_gpu_mirror.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\masm_nugenperf_hotpatch.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\masm_large_content_zero_overhead.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\masm_1m_context_core.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\masm_kv_cache_multiplier.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\avx512_tensor_quant.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\avx512_negative_scale.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\masm_multi_gpu_sync_async.asm

REM Compile C++ modules and link
cl.exe /O2 /GL /Gy /W4 /EHsc /std:c++20 /permissive- ^
   /favor:AMD64 /arch:AVX512 ^
   /I. ^
   Deep2EngineExtensions.cpp ^
   main.cpp ^
   /Fo%OUT_DIR%\ ^
   /link ^
   %OUT_DIR%\*.obj ^
   /SUBSYSTEM:CONSOLE ^
   /LTCG ^
   /OPT:REF ^
   /OPT:ICF ^
   /OUT:%OUT_DIR%\SovereignSweep_X64.exe

if %ERRORLEVEL% NEQ 0 (
    echo [-] Compilation Fault: Build chain failed.
    exit /b %ERRORLEVEL%
)

echo [+] Success: SovereignSweep_X64.exe ready.
