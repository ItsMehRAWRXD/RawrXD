@echo off
REM Short certification-mode run to exercise the repeat-generation traces
REM (the earlier 128-token certification log stopped at the [6] header).
cd /d F:\rawrxd\tools
deep2_runtime_dispatch.exe --model F:\rawrxd\models\nemotron-3.5-lightning-30b-Q4_K_M.gguf --tokens 8 --prompt "def add(a, b):" > F:\rawrxd\cert8_trace_out.log 2> F:\rawrxd\cert8_trace_err.log
