@echo off
REM Compile-test recovered FIMPromptBuilder.cpp against live headers, using the
REM Qt-free agentic_observability override (sandbox only; repo headers untouched).
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (echo VCVARS_FAILED & exit /b 2)

set REC=F:\rawrxd\_bridge_fix\recovered
set RECINC=F:\rawrxd\_bridge_fix\recinc
set OUT=F:\rawrxd\_bridge_fix\recobj
if not exist "%OUT%" mkdir "%OUT%"

set INC=/I %RECINC% /I F:\rawrxd\include /I F:\rawrxd\src /I F:\rawrxd\src\agentic /I F:\rawrxd\src\agents

cl /nologo /c /std:c++20 /MT /EHsc /O2 /permissive- /Zc:__cplusplus %INC% "%REC%\FIMPromptBuilder.cpp" /Fo:"%OUT%\FIMPromptBuilder.obj" > "%OUT%\FIM.log" 2>&1
echo FIM_EXIT=%errorlevel%
if errorlevel 1 (echo --- errors --- & findstr /R /C:"fatal error" /C:"error C" "%OUT%\FIM.log" | findstr /R /V "LNK")
endlocal
