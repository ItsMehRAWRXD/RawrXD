@echo off
setlocal

set ML64_EXE=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK_EXE=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe

if not exist "%ML64_EXE%" set ML64_EXE=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe
if not exist "%LINK_EXE%" set LINK_EXE=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe

set KERNEL32_LIB=D:\rawrxd\scripts\kernel32.lib

echo [BUILD] ================================================
echo [BUILD] Sovereign MMF Agent Clients
echo [BUILD] ================================================

if not exist "%ML64_EXE%" (
  echo [BUILD] ERROR: ml64.exe not found
  exit /b 1
)
if not exist "%LINK_EXE%" (
  echo [BUILD] ERROR: link.exe not found
  exit /b 1
)

"%ML64_EXE%" /c /nologo /W3 /Fo agent_ipc.obj agent_ipc.asm
if errorlevel 1 goto :fail

"%ML64_EXE%" /c /nologo /W3 /Fo agent_control.obj agent_control.asm
if errorlevel 1 goto :fail

"%ML64_EXE%" /c /nologo /W3 /Fo agent_watch.obj agent_watch.asm
if errorlevel 1 goto :fail

"%ML64_EXE%" /c /nologo /W3 /Fo agent_metrics.obj agent_metrics.asm
if errorlevel 1 goto :fail

"%LINK_EXE%" /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:agent_control.exe agent_control.obj agent_ipc.obj "%KERNEL32_LIB%"
if errorlevel 1 goto :fail

"%LINK_EXE%" /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:agent_watch.exe agent_watch.obj agent_ipc.obj "%KERNEL32_LIB%"
if errorlevel 1 goto :fail

"%LINK_EXE%" /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:agent_metrics.exe agent_metrics.obj agent_ipc.obj "%KERNEL32_LIB%"
if errorlevel 1 goto :fail

echo [BUILD] SUCCESS:
echo   - agent_control.exe
echo   - agent_watch.exe
echo   - agent_metrics.exe
exit /b 0

:fail
echo [BUILD] FAILED
exit /b 1
