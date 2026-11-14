@echo off
cd /d "g:\~dev\rawrxd\build_ninja\bin"
set RAWRXD_HOST_DECODE=1
set R1_HOST_FLOOR=1
set RAWRXD_ALLOW_GPU=0
set DEEP2_WEIGHT_BUDGET_MIB=8192
"g:\~dev\rawrxd\build_ninja\bin\rawr.exe" run "g:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" -p "Hello" --max-tokens 8 --receipt "g:\~dev\rawrxd\evidence\ATTN_KV_DEEP2_CPU_001\runs\A_short_hello_8.receipt.json" > "g:\~dev\rawrxd\evidence\ATTN_KV_DEEP2_CPU_001\runs\A_short_hello_8.out.txt" 2> "g:\~dev\rawrxd\evidence\ATTN_KV_DEEP2_CPU_001\runs\A_short_hello_8.err.txt"
set EC=%ERRORLEVEL%
> "g:\~dev\rawrxd\evidence\ATTN_KV_DEEP2_CPU_001\runs\A_short_hello_8.exit.txt" echo EXIT=%EC%