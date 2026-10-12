@echo off
REM Stage 3: archive ABI-matched real agentic objects into libsubagentic.lib.
REM Objects that clean-compiled against the LIVE production headers only.
REM Unresolved cross-references are expected and resolved at final exe link.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (echo VCVARS_FAILED & exit /b 2)

set BF=F:\rawrxd\_bridge_fix
set AO=%BF%\agentic_objs
set IMPL=%BF%\impl
set DUR=%BF%\durable
if not exist "%DUR%" mkdir "%DUR%"

REM ABI-matched agentic objects (clean-compiled vs live headers this session)
set OBJS=%AO%\AgentOrchestrator.obj %AO%\FIMPromptBuilder.obj %AO%\ToolRegistry.obj %AO%\rawrxd_subsystem_api.obj
REM Durable pure-native subsystem fixes already verified (42->10)
set OBJS=%OBJS% %IMPL%\agent_history.obj %IMPL%\agent_policy.obj %IMPL%\autonomous_subagent.obj %IMPL%\hexmag_tuner.obj
REM Native Advanced Agent Coordinator from the probe set (aac)
set OBJS=%OBJS% F:\rawrxd\build_lnk\aac.obj

lib /nologo /OUT:"%DUR%\libsubagentic.lib" %OBJS% > "%BF%\libsubagentic.log" 2>&1
if errorlevel 1 (echo LIB_FAILED & type "%BF%\libsubagentic.log" & exit /b 1)
echo LIB_OK
dumpbin /ARCHIVEMEMBERS "%DUR%\libsubagentic.lib" 2>&1 | findstr /R /C:"\.obj" | findstr /R /V "ARCHIVE" | findstr /R /V "Archive" | find /C /V ""
endlocal
