@echo off
setlocal
cd /d F:\rawrxd-native-agent-001
if not exist evidence mkdir evidence

echo === oracle single-turn %DATE% %TIME% > evidence\oracle_single_turn_meta.txt
echo EXE=F:\llama.cpp-ref\build\bin\llama-cli.exe>> evidence\oracle_single_turn_meta.txt
echo MODEL=F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf>> evidence\oracle_single_turn_meta.txt
echo PROMPT=evidence\first_corpus_prompt.txt>> evidence\oracle_single_turn_meta.txt
echo FLAGS=-c 2048 -n 256 --temp 0 --top-k 1 --seed 0 --single-turn --no-jinja --verbose>> evidence\oracle_single_turn_meta.txt

if not exist evidence\first_corpus_prompt.txt (
  echo MISSING_PROMPT>> evidence\oracle_single_turn_meta.txt
  exit /b 2
)

echo START=%TIME%>> evidence\oracle_single_turn_meta.txt
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
  --single-turn ^
  --no-jinja ^
  --verbose 1>evidence\oracle_single_turn.out 2>evidence\oracle_single_turn.err
set EC=%ERRORLEVEL%
echo EXIT=%EC%>> evidence\oracle_single_turn_meta.txt
echo END=%TIME%>> evidence\oracle_single_turn_meta.txt
for %%A in (evidence\oracle_single_turn.out) do echo OUT_BYTES=%%~zA>> evidence\oracle_single_turn_meta.txt
for %%A in (evidence\oracle_single_turn.err) do echo ERR_BYTES=%%~zA>> evidence\oracle_single_turn_meta.txt
echo EXIT=%EC%
exit /b %EC%
