@echo off
REM DEEP2_SSM_CONV_NUMERICAL_INSTABILITY_001 - observation run.
REM One generation, one token: the post-fix failure is at prefill token 0,
REM so no decode loop is needed to reach the diverging stage.
setlocal
set MODEL=F:\OllamaModels\blobs\sha256-5c19f6282f4fc51cb114cb6c876d70ca2fc3b9cf0fbd0a018d9908f4fe1f63b3
set EXE=F:\~dev\rawrxd\build_memcorrupt_001\deep2_ssmnum_diag.exe
set OUT=F:\~dev\_ssmnum_run001.txt

set RAWRXD_SSM_DIAG_CALLS=400
set PROMPT=Name exactly three primary colors, separated by commas.

"%EXE%" "%MODEL%" --generations 1 --max-tokens 1 --prompt "%PROMPT%" > "%OUT%" 2>&1
set RC=%ERRORLEVEL%
echo PROCESS_EXIT_CODE=%RC%
echo OUT_SIZE=%OUT%
echo RUN_COMPLETE
exit /b 0