@echo off
setlocal
set RAWRXD_ALLOW_GPU=
set RAWRXD_DEEP2_DEBUG=
set RAWRXD_GREEDY=1
set RAWRXD_STAGE_DIGEST=1
set RAWRXD_STAGE_DUMP_MAX_LAYER=2
set SIDE=%~1
if "%SIDE%"=="" exit /b 2
if /I "%SIDE%"=="plain" set RAWRXD_GEMMA_RMSNORM_ONEPLUS=0
if /I "%SIDE%"=="oneplus" set RAWRXD_GEMMA_RMSNORM_ONEPLUS=1
set OUT=F:\rawrxd\tmp_remeasure_011_012_ab\%SIDE%
cd /d F:\rawrxd\build_tip_debug_rel\bin-msvc || exit /b 1
echo START=%DATE% %TIME%> %OUT%\meta.txt
echo SIDE=%SIDE%>> %OUT%\meta.txt
echo RAWRXD_GEMMA_RMSNORM_ONEPLUS=%RAWRXD_GEMMA_RMSNORM_ONEPLUS%>> %OUT%\meta.txt
echo FIX=011_012_AB_STAGE_DIGEST_FORCE_ONEPLUS>> %OUT%\meta.txt
rawr.exe run F:\rawrxd\gemma3-1b-Q2_K.gguf ask --prompt "Say exactly: AGENT_RESULT=5" --max-tokens 1 > %OUT%\stdout.txt 2> %OUT%\stderr.txt
echo EXIT=%ERRORLEVEL%>> %OUT%\meta.txt
echo END=%DATE% %TIME%>> %OUT%\meta.txt
findstr /C:"[STAGE_DIGEST]" /C:"GEMMA_NUMERIC" /C:"GEMMA_NORM_BAKE" /C:"GEMMA_RMSNORM_ONEPLUS_FORCE" /C:"GEMMA_QK_NORM" /C:"sampled token" /C:"[ask]" /C:"PREFILL_DONE" %OUT%\stdout.txt %OUT%\stderr.txt > %OUT%\digest_extract.txt
echo DIGEST_DONE_%SIDE%
endlocal
