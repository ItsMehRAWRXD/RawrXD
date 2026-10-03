@echo off
REM Run the fixed cert harness against Kimi K2
"F:\~dev\kilo_tmp\deep2_streamer_cert_fixed2.exe" --child "F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf" --tokens 1 2>"F:\~dev\kilo_tmp\kimi_k2_stderr.txt" 1>"F:\~dev\kilo_tmp\kimi_k2_stdout.txt"
echo EXIT_CODE=%ERRORLEVEL%