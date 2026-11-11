@echo off
REM Build the AgentOrchestrator (5-symbol) closure from recovered git sources +
REM the coherent native core tree, into impl\. Then the caller relinks the probe.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (echo VCVARS_FAILED & exit /b 2)

set REC=F:\rawrxd\_bridge_fix\recovered
set RECINC=F:\rawrxd\_bridge_fix\recinc
set CORE=F:\rawrxd\~dev\rawrxd\src\core
set IMPL=F:\rawrxd\_bridge_fix\impl
set OUT=F:\rawrxd\_bridge_fix\recobj
if not exist "%IMPL%" mkdir "%IMPL%"

set INC=/I %RECINC% /I F:\rawrxd\include /I F:\rawrxd\src /I F:\rawrxd\src\agentic /I F:\rawrxd\src\agents /I F:\rawrxd\src\core /I F:\rawrxd\~dev\rawrxd\src /I F:\rawrxd\~dev\rawrxd\src\core /I F:\rawrxd\~dev\rawrxd\src\agents
set COMMON=/nologo /c /std:c++20 /MT /EHsc /O2 /permissive- /Zc:__cplusplus %INC%

call :build "%REC%\AgentOrchestrator.cpp" AgentOrchestrator
call :build "%REC%\FIMPromptBuilder.cpp" FIMPromptBuilder
call :build "%REC%\ToolRegistry.cpp" ToolRegistry
call :build "%REC%\AgentOllamaClient.cpp" AgentOllamaClient
call :build "%CORE%\rawrxd_subsystem_api.cpp" rawrxd_subsystem_api
call :build "%CORE%\rawrxd_subsystem_api_impl.cpp" rawrxd_subsystem_api_impl
call :build "%CORE%\unified_hotpatch_manager.cpp" unified_hotpatch_manager
call :build "%CORE%\DiskRecoveryAgent.cpp" DiskRecoveryAgent
exit /b 0

:build
cl %COMMON% "%~1" /Fo:"%IMPL%\%~2.obj" > "%OUT%\%~2.log" 2>&1
if errorlevel 1 (
  echo FAIL %~2
  findstr /R /C:"fatal error" /C:"error C" "%OUT%\%~2.log" | findstr /R /V "LNK" | findstr /B /C:"F:" | findstr /R /C:"error" 
) else (echo OK   %~2)
goto :eof
