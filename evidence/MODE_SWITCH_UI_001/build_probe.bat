@echo off
setlocal
set "OUTDIR=G:\~dev\rawrxd\evidence\MODE_SWITCH_UI_001"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%OUTDIR%"
cl /nologo /O2 /EHsc /W3 /Fe:probe_mode_switch_748b.exe probe_mode_switch_748b.cpp /link /nologo user32.lib kernel32.lib
if errorlevel 1 exit /b 1
probe_mode_switch_748b.exe > probe_run.txt 2>&1
echo EXIT=%ERRORLEVEL%>> probe_run.txt
type probe_run.txt
endlocal
