@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
set REC=F:\rawrxd\_bridge_fix\recovered
set RECINC=F:\rawrxd\_bridge_fix\recinc
set OUT=F:\rawrxd\_bridge_fix\recobj
if not exist "%OUT%" mkdir "%OUT%"
set INC=/I %RECINC% /I F:\rawrxd\include /I F:\rawrxd\src /I F:\rawrxd\src\agentic /I F:\rawrxd\src\agents /I F:\rawrxd\src\core /I F:\rawrxd\~dev\rawrxd\src /I F:\rawrxd\~dev\rawrxd\src\core /I F:\rawrxd\~dev\rawrxd\src\agentic /I F:\rawrxd\~dev\rawrxd\src\agents
cl /nologo /c /std:c++20 /MT /EHsc /O2 /permissive- /Zc:__cplusplus %INC% "%REC%\AgentOrchestrator.cpp" /Fo:"%OUT%\AgentOrchestrator.obj" > "%OUT%\AO.log" 2>&1
echo AO_EXIT=%errorlevel%
if errorlevel 1 (findstr /R /C:"fatal error" /C:"error C" "%OUT%\AO.log" | findstr /R /V "LNK")
