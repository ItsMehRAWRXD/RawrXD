@echo off
setlocal
where cl >nul 2>nul || (
  echo cl.exe not found. Run from a VS x64 developer prompt.
  exit /b 2
)
where link >nul 2>nul || (
  echo link.exe not found. Run from a VS x64 developer prompt.
  exit /b 3
)
cl /nologo /TC /O2 /W4 /GS- /c deep2_nodep_missing15.c smoke_missing15.c
if errorlevel 1 exit /b %errorlevel%
link /nologo /NODEFAULTLIB /ENTRY:mainCRTStartup /SUBSYSTEM:CONSOLE deep2_nodep_missing15.obj smoke_missing15.obj kernel32.lib /OUT:smoke_missing15.exe
if errorlevel 1 exit /b %errorlevel%
smoke_missing15.exe
set RC=%ERRORLEVEL%
echo SMOKE_RC=%RC%
exit /b %RC%
