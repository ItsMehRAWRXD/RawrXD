@echo off
setlocal
set RAWR=F:\rawrxd\build_ide\bin-msvc\rawr.exe
set T15_FILE=F:\rawrxd\t15_test.txt

:: Reset the test file
echo "T15_ORIGINAL" > %T15_FILE%

:: Start rawr and pipe commands
:: We need to send commands after the process starts
(
echo /tools run editFiles path=t15_test.txt oldString=T15_ORIGINAL newString=T15_EDITED_VIA_TOOL
timeout /t 10 /nobreak >nul
echo /quit
timeout /t 5 /nobreak >nul
) | %RAWR% run nemotron-3-nano:4b autonomous --approve-mutations --max-tokens 256 > F:\rawrxd\t15_stdout_cmd.txt 2>&1

echo BUILD_DONE
