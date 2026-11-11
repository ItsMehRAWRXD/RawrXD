@echo off
REM Compile the AgentOrchestrator (5-symbol) closure and link it into the probe.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (echo VCVARS_FAILED & exit /b 2)

set REC=F:\rawrxd\_bridge_fix\recovered
set RECINC=F:\rawrxd\_bridge_fix\recinc
set BF=F:\rawrxd\_bridge_fix
set CORE=F:\rawrxd\~dev\rawrxd\src\core
set IMPL=%BF%\impl
set OUT=%BF%\recobj
if not exist "%IMPL%" mkdir "%IMPL%"
if not exist "%OUT%" mkdir "%OUT%"

set INC=/I %BF%\core /I %RECINC% /I F:\rawrxd\include /I F:\rawrxd\src /I F:\rawrxd\src\agentic /I F:\rawrxd\src\agents /I F:\rawrxd\src\core /I F:\rawrxd\~dev\rawrxd\src /I F:\rawrxd\~dev\rawrxd\src\core /I F:\rawrxd\~dev\rawrxd\src\agents
set COMMON=/nologo /c /std:c++20 /MT /EHsc /O2 /permissive- /Zc:__cplusplus %INC%

call :build "%BF%\ToolRegistry.cpp" ToolRegistry
call :build "%REC%\AgentOllamaClient.cpp" AgentOllamaClient
call :build "%CORE%\rawrxd_subsystem_api.cpp" rawrxd_subsystem_api
echo --- relink probe ---
call "%BF%\repro_link.cmd"
exit /b 0

:build
cl %COMMON% "%~1" /Fo:"%IMPL%\%~2.obj" > "%OUT%\%~2.log" 2>&1
if errorlevel 1 (
  echo FAIL %~2
  findstr /R /C:"error C" /C:"fatal error" "%OUT%\%~2.log" | findstr /B /C:"F:" | findstr /R /C:"error" 
) else (echo OK   %~2)
goto :eof
