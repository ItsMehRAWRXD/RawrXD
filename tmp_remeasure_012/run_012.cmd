@echo off
setlocal
set RAWRXD_ALLOW_GPU=
set RAWRXD_DEEP2_DEBUG=
set RAWRXD_GREEDY=1
cd /d F:\rawrxd\build_tip_debug_rel\bin-msvc || exit /b 1
if exist F:\rawrxd\tmp_remeasure_012\stdout.txt del /f F:\rawrxd\tmp_remeasure_012\stdout.txt
if exist F:\rawrxd\tmp_remeasure_012\stderr.txt del /f F:\rawrxd\tmp_remeasure_012\stderr.txt
certutil -hashfile rawr.exe SHA256 > F:\rawrxd\tmp_remeasure_012\sha.txt
echo START=%DATE% %TIME%> F:\rawrxd\tmp_remeasure_012\meta.txt
echo FIX=GEMMA_RMSNorm_1plus_w>> F:\rawrxd\tmp_remeasure_012\meta.txt
rawr.exe run F:\rawrxd\gemma3-1b-Q2_K.gguf ask --prompt "Say exactly: AGENT_RESULT=5" --max-tokens 32 > F:\rawrxd\tmp_remeasure_012\stdout.txt 2> F:\rawrxd\tmp_remeasure_012\stderr.txt
echo EXIT=%ERRORLEVEL%>> F:\rawrxd\tmp_remeasure_012\meta.txt
echo END=%DATE% %TIME%>> F:\rawrxd\tmp_remeasure_012\meta.txt
findstr /C:"GEMMA_NUMERIC" /C:"GREEDY" /C:"ASK_PATH" /C:"PREFILL_DONE" /C:"sampled token" /C:"[ask]" F:\rawrxd\tmp_remeasure_012\stdout.txt F:\rawrxd\tmp_remeasure_012\stderr.txt
echo REMEASURE_012_DONE
endlocal
