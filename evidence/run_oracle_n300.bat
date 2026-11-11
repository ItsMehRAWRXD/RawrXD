@echo off
setlocal
cd /d F:\rawrxd-native-agent-001
echo === oracle n=300 ignore-eos %DATE% %TIME% > evidence\oracle_n300_meta.txt
echo ENGINE=llama-cli>> evidence\oracle_n300_meta.txt
echo START=%TIME%>> evidence\oracle_n300_meta.txt
F:\llama.cpp-ref\build\bin\llama-cli.exe ^
  -m F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf ^
  -f evidence\first_corpus_prompt.txt ^
  -c 2048 ^
  -n 300 ^
  --temp 0 ^
  --top-k 1 ^
  --top-p 1.0 ^
  --min-p 0.0 ^
  --repeat-penalty 1.0 ^
  --seed 0 ^
  --ignore-eos ^
  --single-turn ^
  --no-jinja ^
  --verbose 1>evidence\oracle_n300.out 2>evidence\oracle_n300.err
set EC=%ERRORLEVEL%
echo EXIT=%EC%>> evidence\oracle_n300_meta.txt
echo END=%TIME%>> evidence\oracle_n300_meta.txt
for %%A in (evidence\oracle_n300.err) do echo ERR_BYTES=%%~zA>> evidence\oracle_n300_meta.txt
echo EXIT=%EC%
exit /b %EC%
