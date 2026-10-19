@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d R:\smoke_bin
set RAWR_MAX_TOKENS=8
set DEEP2_MAX_TOKENS=8
set RAWRXD_HOST_DECODE=1
set DEEP2_MINIMAL_ENHANCE=1
set RAWRXD_ENABLE_GOVERNOR=
set RAWRXD_ENABLE_70B_HOTPATCH=
set RAWRXD_ENABLE_LAYER_EVICTION=
set OLLAMA_HOST=
set EV=R:\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_MATRIX_001
set EXE=R1MATRIX_HOSTDECODE.exe
set PASS=0
set FAIL=0
if exist "%EV%\BATCH_SUMMARY.txt" del "%EV%\BATCH_SUMMARY.txt"

call :ONE M01_tinyllama_Q4_K_M "R:\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
call :ONE M02_gemma3_1b_Q2_K "R:\gemma3-1b-Q2_K.gguf"
call :ONE M03_phi3_mini_Q2_K "R:\phi3-mini-Q2_K.gguf"
call :ONE M04_llama32_3b_Q2_K "R:\llama3.2-3b-Q2_K.gguf"
call :ONE M05_llama32_3b_Q3_K_S "R:\llama3.2-3b-Q3_K_S.gguf"
call :ONE M06_phi3_mini_Q8_0 "F:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf"
call :ONE M07_nemotron_4b_Q8_0 "F:\OllamaModels\NVIDIA-Nemotron-3-Nano-4B-GGUF\NVIDIA-Nemotron-3-Nano-4B-Q8_0.gguf"
call :ONE M08_deepseek_r1_qwen3_8b_Q4 "F:\OllamaModels\DeepSeek-R1-0528-Qwen3-8B-GGUF\DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf"
call :ONE M09_gemma4_E4B_Q4_K_M "F:\OllamaModels\gemma-4-E4B-it-GGUF\gemma-4-E4B-it-Q4_K_M.gguf"
call :ONE M10_ministral3_Q4_0 "G:\~dev\ministral3_q4_0.gguf"

echo PASS_COUNT=!PASS! FAIL_COUNT=!FAIL! > "%EV%\BATCH_SUMMARY.txt"
echo DONE PASS=!PASS! FAIL=!FAIL!
exit /b 0

:ONE
set ID=%~1
set MODEL=%~2
echo === !ID! ===
"%EXE%" --headless --oneshot --model "!MODEL!" --prompt "say hi" --dir "R:\" > "%EV%\WITNESS_OUT_!ID!.txt" 2> "%EV%\WITNESS_ERR_!ID!.txt"
set EC=!ERRORLEVEL!
findstr /C:"PRODUCT_PASS=1" "%EV%\WITNESS_ERR_!ID!.txt" >nul
if errorlevel 1 (
  echo FAIL !ID! exit=!EC!
  set /a FAIL+=1
  echo ID=!ID! EXIT=!EC! VERDICT=FAIL>> "%EV%\BATCH_SUMMARY.txt"
) else (
  echo PASS !ID! exit=!EC!
  set /a PASS+=1
  echo ID=!ID! EXIT=!EC! VERDICT=PASS>> "%EV%\BATCH_SUMMARY.txt"
)
exit /b 0
