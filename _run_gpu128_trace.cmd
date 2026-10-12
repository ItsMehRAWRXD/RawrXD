@echo off
REM Diagnostic re-run of the uploaded GPU-only capture with unbuffered stderr
REM traces separated from block-buffered stdout.
cd /d F:\rawrxd\tools
deep2_runtime_dispatch.exe --model F:\rawrxd\models\nemotron-3.5-lightning-30b-Q4_K_M.gguf --tokens 128 --prompt "def add(a, b):" --gpu-only > F:\rawrxd\gpu128_trace_out.log 2> F:\rawrxd\gpu128_trace_err.log
