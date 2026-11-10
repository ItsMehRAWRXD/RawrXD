@echo off
setlocal ENABLEDELAYEDEXPANSION
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul
set OUT=F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\live_issue49_loop527_cmd
if exist "%OUT%\agent.stdout.log" del /F /Q "%OUT%\agent.stdout.log" >nul 2>&1
if exist "%OUT%" rmdir /S /Q "%OUT%" 2>nul
mkdir "%OUT%" 2>nul
mkdir "%OUT%\.cursor\rules" 2>nul
copy /Y "g:\~dev\.cursor\rules\PassiveRoleNotRoleplay.mdc" "%OUT%\.cursor\rules\PassiveRoleNotRoleplay.mdc" >nul
> "%OUT%\bug.cpp" echo #include ^<cstdio^>
>>"%OUT%\bug.cpp" echo int add(int a, int b) { return a - b; }
>>"%OUT%\bug.cpp" echo int main() { std::printf("AGENT_RESULT=%%d\n", add(2, 3)); return 0; }
set LOOP=F:\rawrxd\build_tip_debug_rel\bin\deep2_agentic_loop.exe
set BUILD=cl /nologo /EHsc /std:c++20 /Fe:"%OUT%\bug.exe" "%OUT%\bug.cpp"
set RUN=%OUT%\bug.exe
set MODEL=bigdaddyg-productivity-local:latest
echo OUT=%OUT%
echo MODEL=%MODEL%
echo START=%TIME%
"%LOOP%" --provider ollama --model %MODEL% --workdir "%OUT%" --target-file bug.cpp --build-command "%BUILD%" --run-command "%RUN%" --max-steps 12 --max-wall-time-sec 600 --expected-output AGENT_RESULT=5 > "%OUT%\agent.stdout.log" 2> "%OUT%\agent.stderr.log"
set RC=!ERRORLEVEL!
echo LOOP_EXIT=!RC!> "%OUT%\exitcode.txt"
echo END=%TIME%
echo LOOP_EXIT=!RC!
findstr /C:"OLLAMA_AGENT" /C:"write_body" /C:"AGENT_RESULT" /C:"TOOL=" /C:"request failed" "%OUT%\agent.stdout.log"
endlocal
