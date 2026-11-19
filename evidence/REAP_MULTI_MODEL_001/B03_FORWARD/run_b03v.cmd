@echo off
setlocal
set R1_HOST_FLOOR=1
set RAWRXD_ALLOW_GPU=
set OUT=g:\~dev\rawrxd\evidence\REAP_MULTI_MODEL_001\B03_FORWARD
"g:\~dev\rawrxd\build_ninja\bin\rawr.exe" run "F:\ollamamodels\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf" --reap 30GB/8 -p Hello --max-tokens 4 --receipt "%OUT%\minimax_b03v.json" > "%OUT%\minimax_b03v.out.txt" 2> "%OUT%\minimax_b03v.err.txt"
echo EXIT=%ERRORLEVEL%> "%OUT%\minimax_b03v.exit.txt"
type "%OUT%\minimax_b03v.exit.txt"
endlocal
