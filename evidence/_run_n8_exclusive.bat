@echo off
setlocal
echo START=%DATE% %TIME%> "F:\rawrxd-native-agent-001\evidence\k2_probe_n8_meta.txt"
echo ENGINE=llama-completion exclusive cmd>> "F:\rawrxd-native-agent-001\evidence\k2_probe_n8_meta.txt"
"F:\llama.cpp-ref\build-vulkan\bin\llama-completion.exe" -m "F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf" -f "F:\rawrxd-native-agent-001\evidence\first_corpus_prompt.txt" -c 512 -n 8 --temp 0 --top-k 1 --top-p 1.0 --min-p 0.0 --repeat-penalty 1.0 --seed 0 --ignore-eos --no-display-prompt -no-cnv --verbose --no-warmup --load-mode mmap --no-repack --cpu-moe --fit on -ngl 99 --device Vulkan0,Vulkan1 1> "F:\rawrxd-native-agent-001\evidence\k2_probe_n8.out" 2> "F:\rawrxd-native-agent-001\evidence\k2_probe_n8.err"
echo EXIT=%ERRORLEVEL% END=%DATE% %TIME%>> "F:\rawrxd-native-agent-001\evidence\k2_probe_n8_meta.txt"
exit /b %ERRORLEVEL%
