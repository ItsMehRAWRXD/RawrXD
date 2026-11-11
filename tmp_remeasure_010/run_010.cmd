@echo off
setlocal EnableExtensions
set OUTDIR=F:\rawrxd\tmp_remeasure_010
mkdir "%OUTDIR%" 2>nul
set RAWRXD_ALLOW_GPU=
set RAWRXD_DEEP2_DEBUG=
set RAWRXD_GREEDY=1
set EXE=F:\rawrxd\build_tip_debug_rel\bin-msvc\rawr.exe
set SHA=9f7d35ac6b680acb8d1834247abd475e2a27b69b60f0390e0c2c9b66c0e0e9c0
echo EXE_SHA=%SHA%> "%OUTDIR%\meta.txt"
echo ARGS=run F:\rawrxd\gemma3-1b-Q2_K.gguf ask --prompt "Say exactly: AGENT_RESULT=5" --max-tokens 32>> "%OUTDIR%\meta.txt"
echo FIX=generateChat+configureGeneration_greedy>> "%OUTDIR%\meta.txt"
echo START=%DATE% %TIME%>> "%OUTDIR%\meta.txt"
cd /d F:\rawrxd\build_tip_debug_rel\bin-msvc
"%EXE%" run F:\rawrxd\gemma3-1b-Q2_K.gguf ask --prompt "Say exactly: AGENT_RESULT=5" --max-tokens 32 > "%OUTDIR%\stdout.txt" 2> "%OUTDIR%\stderr.txt"
set EXITCODE=%ERRORLEVEL%
echo EXIT=%EXITCODE%>> "%OUTDIR%\meta.txt"
echo END=%DATE% %TIME%>> "%OUTDIR%\meta.txt"
echo EXIT=%EXITCODE%
echo REMEASURE_010_DONE
exit /b %EXITCODE%
