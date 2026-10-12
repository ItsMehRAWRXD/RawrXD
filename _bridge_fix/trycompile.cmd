@echo off
REM Compile each recovered real source against the LIVE headers to measure the
REM true residual dependency closure for the 10 remaining bridge symbols.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (echo VCVARS_FAILED & exit /b 2)

set REC=F:\rawrxd\_bridge_fix\recovered
set OUT=F:\rawrxd\_bridge_fix\recobj
if not exist "%OUT%" mkdir "%OUT%"

set INC=/I F:\rawrxd\src /I F:\rawrxd\src\agentic /I F:\rawrxd\src\agents /I F:\rawrxd\src\core

for %%s in (FIMPromptBuilder.cpp Planner.cpp AgentMemory.cpp) do (
  echo ===== %%s =====
  cl /nologo /c /std:c++20 /MT /EHsc /O2 /permissive- /Zc:__cplusplus %INC% "%REC%\%%s" /Fo:"%OUT%\%%s.obj" > "%OUT%\%%s.log" 2>&1
  echo   %%s exit=!errorlevel!
  if errorlevel 1 (findstr /R /C:"error" "%OUT%\%%s.log" | findstr /R "_C___3263_" >nul 2>&1)
  if errorlevel 1 (echo   --- first errors --- & findstr /R /C:"fatal error" /C:"error C" "%OUT%\%%s.log" | findstr /R /V "LNK" )
)

for %%s in (AgentOrchestrator.cpp ToolRegistry.cpp AgentOllamaClient.cpp CEOAgent.cpp) do (
  echo ===== %%s =====
  cl /nologo /c /std:c++20 /MT /EHsc /O2 /permissive- /Zc:__cplusplus %INC% "%REC%\%%s" /Fo:"%OUT%\%%s.obj" > "%OUT%\%%s.log" 2>&1
  echo   %%s exit=!errorlevel!
  if errorlevel 1 (echo   --- first errors --- & findstr /R /C:"fatal error" /C:"error C" "%OUT%\%%s.log" | findstr /R /V "LNK" )
)
endlocal
