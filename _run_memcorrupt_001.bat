@echo off
REM DEEP2_MEMORY_CORRUPTION_ROOT_001 - instrumented run with exit-code capture.
REM Same binary, same HEAD, same working directory, same arguments, same
REM environment. The raw NTSTATUS is written to a file so the classification
REM cannot rest on the console text alone.
setlocal
set MODEL=F:\OllamaModels\blobs\sha256-5c19f6282f4fc51cb114cb6c876d70ca2fc3b9cf0fbd0a018d9908f4fe1f63b3
set EXE=F:\~dev\rawrxd\build_memcorrupt_001\deep2_lifecycle_diag.exe
set OUT=F:\~dev\_memcorrupt_run001.txt
set EC=F:\~dev\_memcorrupt_run001.exitcode.txt

set PROMPT=Name exactly three primary colors, separated by commas.

"%EXE%" "%MODEL%" --generations 4 --max-tokens 64 --prompt "%PROMPT%" > "%OUT%" 2>&1
set RC=%ERRORLEVEL%

> "%EC%" echo PROCESS_EXIT_CODE=%RC%
>>"%EC%" echo HEX=0x%PROCESS_EXIT_DEC%
set /a "NEG=-1"
set /a "U=%RC%" 2>nul
if "%U%" GEQ "2147483648" (
  set /a "H=%U:~8,1%%U:~9,1%%U:~10,1%%U:~11,1%%U:~12,1%%U:~13,1%%U:~14,1%%U:~15,1%"
  >>"%EC%" echo NTSTATUS=0xC000%H:~6,2%%H:~4,2%%H:~2,2%%H:~0,2%
)
echo RUN_COMPLETE
type "%EC%"
exit /b 0