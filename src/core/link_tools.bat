@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\src\core
link /DEBUG /OUT:AgenticUnified.exe agentic_orchestrator.obj tool_registry.obj kernel32.lib /SUBSYSTEM:CONSOLE /ENTRY:AgenticUnifiedMain
if errorlevel 1 (
    echo Link failed
    exit /b 1
)
echo Link succeeded
AgenticUnified.exe
pause
