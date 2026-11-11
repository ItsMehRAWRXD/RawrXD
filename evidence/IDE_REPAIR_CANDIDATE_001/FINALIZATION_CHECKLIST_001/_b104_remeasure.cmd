@echo off
setlocal
set EXE=F:\rawrxd\build_tip_debug_rel\bin-msvc\rawr.exe
set OUTDIR=F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\FINALIZATION_CHECKLIST_001
rem Tip CLI (ECE828A8): positional after model is MODE, not prompt.
rem Product remasure form: --backend ollama --mode ask --goal TEXT
rem --max-tokens ignored by this binary (unknown flag swallowed).
"%EXE%" run qwen3:8b --backend ollama --mode ask --goal "Say exactly: AGENT_RESULT=5" --max-tokens=16 >"%OUTDIR%\_remeasure_stdout.txt" 2>"%OUTDIR%\_remeasure_stderr.txt"
echo EXIT=%ERRORLEVEL%
endlocal
