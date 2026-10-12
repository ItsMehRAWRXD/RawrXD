@echo off
REM Full-length certification-mode run (128 tokens) -- the earlier run of this
REM shape stopped at the [6] repeat-generation header. Traces decide whether
REM that was a stall or a capture taken mid-replay.
cd /d F:\rawrxd\tools
deep2_runtime_dispatch.exe --model F:\rawrxd\models\nemotron-3.5-lightning-30b-Q4_K_M.gguf --tokens 128 --prompt "def add(a, b):" > F:\rawrxd\cert128_trace_out.log 2> F:\rawrxd\cert128_trace_err.log
