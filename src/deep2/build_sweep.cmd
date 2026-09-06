@echo off
REM =====================================================================================
REM Subsystem: Production Performance Sweep Build Chain (Simplified)
REM =====================================================================================

set OUT_DIR=.\dist
if not exist %OUT_DIR% mkdir %OUT_DIR%

echo [*] Compiling Production-Hardened Performance Sweep Binary...

REM MASM Module Path
set MASM_PATH=..\..\..\RawrXD-production-lazy-init\src\masm\final-ide

REM Compile MASM modules
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\masm_core_thread_affinity.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\avx512_tensor_quant.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\avx512_negative_scale.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\masm_multi_gpu_sync_async.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\masm_core_profiler.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\MasmVramStreamKernel.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\masm_moe_expert_gate.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\masm_core_gemv_avx512.asm
ml64.exe /c /Cx /Fo %OUT_DIR%\ %MASM_PATH%\masm_kv_cache_multiplier.asm

REM Compile C++ and link
cl.exe /O2 /W4 /EHsc /std:c++20 /I. ^
   Deep2FinalSweep.cpp ^
   Deep2EngineExtensions.cpp ^
   main.cpp ^
   /Fo%OUT_DIR%\ ^
   /link ^
   %OUT_DIR%\*.obj ^
   kernel32.lib user32.lib gdi32.lib shell32.lib ole32.lib advapi32.lib ^
   /OUT:%OUT_DIR%\SovereignSweep_X64.exe

if %ERRORLEVEL% NEQ 0 (
    echo [-] Build Fault: Failed to generate production sweep binary.
    exit /b %ERRORLEVEL%
)

echo [+] Success: SovereignSweep_X64.exe ready.
