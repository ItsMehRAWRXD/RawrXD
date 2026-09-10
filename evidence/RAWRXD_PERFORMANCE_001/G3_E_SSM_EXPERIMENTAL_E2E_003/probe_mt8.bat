@echo off
setlocal
set RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM=1
set RAWRXD_HOST_DECODE=1
set RAWRXD_DEEP2_ALLOW_ELASTIC=0
set DEEP2_DUALSTICK_ARM=0
set DEEP2_MINIMAL_ENHANCE=1
set RAWRXD_DEEP2_NEMOTRON_SSM_SCAN=
set EV=G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_E_SSM_EXPERIMENTAL_E2E_003
set EXE=G:\~dev\rawrxd\build-fd\bin\rawr.exe
set MODEL=G:\~dev\rawrxd\_r1_iso\03_nemotron\NVIDIA-Nemotron-3-Nano-4B-Q8_0.gguf
"%EXE%" run "%MODEL%" hi --max-tokens 8 >"%EV%\LIVE.out.txt" 2>"%EV%\LIVE.err.txt"
echo EXIT=%ERRORLEVEL%>"%EV%\LIVE.exit.txt"
type "%EV%\LIVE.exit.txt"
