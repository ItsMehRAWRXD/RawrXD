@echo off
setlocal

set "ROOT=%~dp0\..\.."
set "OUT=%ROOT%\build\p1_outcome_reverse_runtime_x64"

if not exist "%OUT%" mkdir "%OUT%"

where ml64.exe >nul 2>nul
if errorlevel 1 (
    echo [P1OR] ml64.exe is not on PATH. Run from an x64 Native Tools prompt.
    exit /b 90
)

where link.exe >nul 2>nul
if errorlevel 1 (
    echo [P1OR] link.exe is not on PATH. Run from an x64 Native Tools prompt.
    exit /b 91
)

ml64.exe /nologo /c /W3 /I "%ROOT%\src\asm" /Fo"%OUT%\runtime.obj" "%ROOT%\src\asm\P1_OutcomeReverseRuntime_x64.asm"
if errorlevel 1 exit /b %errorlevel%

ml64.exe /nologo /c /W3 /I "%ROOT%\src\asm" /Fo"%OUT%\smoke.obj" "%ROOT%\tests\masm\P1_OutcomeReverseRuntime_Smoke_x64.asm"
if errorlevel 1 exit /b %errorlevel%

link.exe /nologo /machine:x64 /subsystem:console /entry:mainCRTStartup /nodefaultlib /dynamicbase /nxcompat /out:"%OUT%\P1_OutcomeReverseRuntime_Smoke_x64.exe" "%OUT%\runtime.obj" "%OUT%\smoke.obj"
if errorlevel 1 exit /b %errorlevel%

"%OUT%\P1_OutcomeReverseRuntime_Smoke_x64.exe"
set "P1OR_RC=%errorlevel%"

if "%P1OR_RC%"=="0" (
    echo P1_OUTCOME_REVERSE_RUNTIME_001=PASS
) else (
    echo P1_OUTCOME_REVERSE_RUNTIME_001=FAIL EXIT=%P1OR_RC%
)

exit /b %P1OR_RC%
