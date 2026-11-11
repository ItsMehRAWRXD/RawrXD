@echo off
setlocal
set E=F:\rawrxd\evidence\GAP_AUDIT_2026-10-13\gate5
set M=F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
set TOKENS_FILE=%E%\tokens_long.txt
mkdir "%E%\ref_head" 2>nul
mkdir "%E%\d2_cpu_head" 2>nul
mkdir "%E%\d2_gpu_head" 2>nul

echo [gate5-head] regenerating llama.cpp reference (129 teacher-forced positions)
"F:\rawrxd\tmp_llama-clone\build\bin\Release\llama_dump_logits_teacher_forced.exe" "%M%" "%TOKENS_FILE%" "%E%\ref_head" 32000 > "%E%\ref_head.log" 2>&1
echo [gate5-head] ref_rc=%errorlevel%

echo [gate5-head] Deep2 CPU-native sweep
"F:\rawrxd\tools\deep2_parity_trace.exe" --model "%M%" --tokens "@TOKENS@" --outdir "%E%\d2_cpu_head" > "%E%\d2_cpu_head.log" 2>&1
echo [gate5-head] cpu_rc=%errorlevel%

echo [gate5-head] Deep2 GPU-native sweep
"F:\rawrxd\tools\deep2_parity_trace.exe" --model "%M%" --tokens "@TOKENS@" --outdir "%E%\d2_gpu_head" --gpu > "%E%\d2_gpu_head.log" 2>&1
echo [gate5-head] gpu_rc=%errorlevel%

echo [gate5-head] SWEEP_DONE
