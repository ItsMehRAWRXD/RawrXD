@echo off
setlocal EnableExtensions
rem Short backend/offload probe — NOT a Gate2 256-window seal.
set "ROOT=F:\rawrxd-native-agent-001"
set "EXE=F:\llama.cpp-ref\build-vulkan\bin\llama.exe"
set "MODEL=F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf"
set "PROMPT=%ROOT%\evidence\first_corpus_prompt.txt"
set "OUT=%ROOT%\evidence\k2_probe_n8.out"
set "ERR=%ROOT%\evidence\k2_probe_n8.err"
set "META=%ROOT%\evidence\k2_probe_n8_meta.txt"
echo START=%DATE% %TIME%> "%META%"
cd /d "%ROOT%"
"%EXE%" cli -m "%MODEL%" -f "%PROMPT%" -c 512 -n 8 --temp 0 --top-k 1 --top-p 1.0 --min-p 0.0 --repeat-penalty 1.0 --seed 0 --single-turn --no-jinja --ignore-eos --verbose --load-mode mmap --no-repack --cpu-moe --fit on -ngl 99 --device Vulkan0,Vulkan1 1> "%OUT%" 2> "%ERR%"
set "RC=%ERRORLEVEL%"
echo EXIT=%RC% END=%DATE% %TIME%>> "%META%"
exit /b %RC%
