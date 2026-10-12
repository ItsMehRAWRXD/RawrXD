@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
set REC=F:\rawrxd\_bridge_fix\recovered
set RECINC=F:\rawrxd\_bridge_fix\recinc
set BF=F:\rawrxd\_bridge_fix
set OUT=%BF%\recobj
set INC=/I %RECINC% /I F:\rawrxd\include /I F:\rawrxd\src /I F:\rawrxd\src\agentic /I F:\rawrxd\src\agents /I F:\rawrxd\src\core /I %BF% /I %BF%\core /I F:\rawrxd\~dev\rawrxd\src /I F:\rawrxd\~dev\rawrxd\src\core
cl /nologo /c /std:c++20 /MT /EHsc /O2 /permissive- /Zc:__cplusplus %INC% "%REC%\AgentOllamaClient.cpp" /Fo:"%OUT%\AgentOllamaClient.obj" > "%OUT%\AC.log" 2>&1
echo AC_EXIT=%errorlevel%
