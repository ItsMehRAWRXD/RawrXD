@echo off
setlocal
set RAWRXD_ALLOW_GPU=
set RAWRXD_DEEP2_DEBUG=
set RAWRXD_GREEDY=1
set RAWRXD_STAGE_DIGEST=1
set RAWRXD_STAGE_DUMP_MAX_LAYER=2
cd /d F:\rawrxd\build_tip_debug_rel\bin-msvc || exit /b 1
certutil -hashfile rawr.exe SHA256 > F:\rawrxd\tmp_remeasure_016_div\sha.txt
echo START=%DATE% %TIME%> F:\rawrxd\tmp_remeasure_016_div\meta.txt
echo FIX=STAGE_DIGEST_EARLIEST_DIVERGENCE_NO_SCALE>> F:\rawrxd\tmp_remeasure_016_div\meta.txt
rawr.exe run F:\rawrxd\gemma3-1b-Q2_K.gguf ask --prompt "Say exactly: AGENT_RESULT=5" --max-tokens 1 > F:\rawrxd\tmp_remeasure_016_div\stdout.txt 2> F:\rawrxd\tmp_remeasure_016_div\stderr.txt
echo EXIT=%ERRORLEVEL%>> F:\rawrxd\tmp_remeasure_016_div\meta.txt
echo END=%DATE% %TIME%>> F:\rawrxd\tmp_remeasure_016_div\meta.txt
findstr /C:"[STAGE_DIGEST]" /C:"GEMMA_NUMERIC" /C:"GEMMA_NORM_BAKE" /C:"GEMMA_QK_NORM" /C:"sampled token" /C:"[ask]" /C:"PREFILL_DONE" F:\rawrxd\tmp_remeasure_016_div\stdout.txt F:\rawrxd\tmp_remeasure_016_div\stderr.txt > F:\rawrxd\tmp_remeasure_016_div\digest_extract.txt
echo DIGEST_DONE
endlocal
