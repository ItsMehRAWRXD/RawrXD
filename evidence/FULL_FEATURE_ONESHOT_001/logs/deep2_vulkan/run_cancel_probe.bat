@echo off
set EXE=F:\rawrxd\build\bin\Release\deep2_bench_tps.exe
set MODEL=F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf
"%EXE%" --model "%MODEL%" --tokens "1 185" --decode 128 --runs 1 --device 0
