@echo off
setlocal
cd /d F:\rawrxd-native-agent-001
if not exist evidence mkdir evidence

echo === oracle non-interactive probe %DATE% %TIME% > evidence\oracle_probe_meta.txt
echo EXE=F:\llama.cpp-ref\build\bin\llama-cli.exe>> evidence\oracle_probe_meta.txt
echo MODEL=F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf>> evidence\oracle_probe_meta.txt
echo CORPUS=F:\rawrxd-native-agent-001\corpus.jsonl>> evidence\oracle_probe_meta.txt
echo N=256 TEMP=0 TOP_K=1 SEED=0 NO_CONVERSATION=1>> evidence\oracle_probe_meta.txt

if not exist "F:\llama.cpp-ref\build\bin\llama-cli.exe" (
  echo MISSING_EXE>> evidence\oracle_probe_meta.txt
  exit /b 2
)
if not exist "F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf" (
  echo MISSING_MODEL>> evidence\oracle_probe_meta.txt
  exit /b 2
)
if not exist "F:\rawrxd-native-agent-001\corpus.jsonl" (
  echo MISSING_CORPUS>> evidence\oracle_probe_meta.txt
  exit /b 2
)

echo START=%TIME%>> evidence\oracle_probe_meta.txt
F:\llama.cpp-ref\build\bin\llama-cli.exe ^
  -m F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf ^
  -f F:\rawrxd-native-agent-001\corpus.jsonl ^
  -c 2048 ^
  -n 256 ^
  --temp 0 ^
  --top-k 1 ^
  --top-p 1.0 ^
  --min-p 0.0 ^
  --repeat-penalty 1.0 ^
  --seed 0 ^
  --no-conversation ^
  --no-display-prompt ^
  --verbose 1>evidence\oracle_probe_raw.out 2>evidence\oracle_probe_raw.err
set EC=%ERRORLEVEL%
echo EXIT=%EC%>> evidence\oracle_probe_meta.txt
echo END=%TIME%>> evidence\oracle_probe_meta.txt
for %%A in (evidence\oracle_probe_raw.out) do echo OUT_BYTES=%%~zA>> evidence\oracle_probe_meta.txt
for %%A in (evidence\oracle_probe_raw.err) do echo ERR_BYTES=%%~zA>> evidence\oracle_probe_meta.txt
echo EXIT=%EC%
exit /b %EC%
