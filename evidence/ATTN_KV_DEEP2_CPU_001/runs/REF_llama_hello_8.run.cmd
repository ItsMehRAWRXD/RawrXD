@echo off
"G:\~dev\llama-direct\vulkan\llama-cli.exe" -m "g:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" -p Hello -n 8 -ngl 0 --temp 0 -c 2048 > "g:\~dev\rawrxd\evidence\ATTN_KV_DEEP2_CPU_001\runs\REF_llama_hello_8.out.txt" 2> "g:\~dev\rawrxd\evidence\ATTN_KV_DEEP2_CPU_001\runs\REF_llama_hello_8.err.txt"
set EC=%ERRORLEVEL%
> "g:\~dev\rawrxd\evidence\ATTN_KV_DEEP2_CPU_001\runs\REF_llama_hello_8.exit.txt" echo EXIT=%EC%