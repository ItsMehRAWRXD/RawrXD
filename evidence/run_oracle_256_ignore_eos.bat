@echo off
setlocal
cd /d F:\rawrxd-native-agent-001
if not exist evidence\first_corpus_prompt.txt (
  echo MISSING_PROMPT
  exit /b 2
)

echo === oracle 256 ignore-eos %DATE% %TIME% > evidence\oracle_256_meta.txt
echo FLAGS=-n 256 --ignore-eos --single-turn --no-jinja --temp 0 --seed 0>> evidence\oracle_256_meta.txt
echo START=%TIME%>> evidence\oracle_256_meta.txt

F:\llama.cpp-ref\build\bin\llama-cli.exe ^
  -m F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf ^
  -f evidence\first_corpus_prompt.txt ^
  -c 2048 ^
  -n 256 ^
  --temp 0 ^
  --top-k 1 ^
  --top-p 1.0 ^
  --min-p 0.0 ^
  --repeat-penalty 1.0 ^
  --seed 0 ^
  --ignore-eos ^
  --single-turn ^
  --no-jinja ^
  --verbose 1>evidence\oracle_256.out 2>evidence\oracle_256.err

set EC=%ERRORLEVEL%
echo EXIT=%EC%>> evidence\oracle_256_meta.txt
echo END=%TIME%>> evidence\oracle_256_meta.txt
for %%A in (evidence\oracle_256.out) do echo OUT_BYTES=%%~zA>> evidence\oracle_256_meta.txt
for %%A in (evidence\oracle_256.err) do echo ERR_BYTES=%%~zA>> evidence\oracle_256_meta.txt
echo EXIT=%EC%
exit /b %EC%
